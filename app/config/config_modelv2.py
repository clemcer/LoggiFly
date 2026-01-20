from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    Field,
)
from typing import Literal
from enum import Enum
import re
from constants import SUPPORTED_CONTAINER_ACTIONS, SUPPORTED_CONTAINER_EVENTS, MonitorType
from typing import List, Optional, Union, ClassVar, Annotated, Any
import logging

def validate_action_cooldown(v):
    """
    Validate action cooldown value with minimum threshold enforcement.
    """
    if v is None:
        return None
    try:
        v = int(v)
    except Exception as e:
        raise ValueError(f"Action cooldown must be an integer. {e}")
    if v < 10:
        logging.warning("Action cooldown must be at least 10 seconds. Setting to 10 seconds")
        return 10
    return v

class BaseConfigModel(BaseModel):
    """Base configuration model with common Pydantic settings."""
    model_config = ConfigDict(
        extra="forbid", # TODO: change later, possibly configurable by env
        validate_default=True,
        use_enum_values=True,
        from_attributes=False,
        arbitrary_types_allowed=False,
    )

class IgnoreKeywordItem(BaseConfigModel):
    # Can be simple string or regex
    keyword: Optional[str] = None
    regex: Optional[str] = None

class OliveTinArgument(BaseConfigModel):
    name: str
    value: str

class OliveTinAction(BaseConfigModel):
    id: str
    arguments: Optional[List[OliveTinArgument]] = None

    @field_validator("arguments", mode="before")
    def validate_olivetin_arguments(cls, v):
        if not v:
            return None
        if not isinstance(v, list):
            raise ValueError(f"OliveTin Action: arguments must be a list. Ignoring for argument(s) '{v}'.")
        filtered_args = []
        for arg in v:
            if not isinstance(arg, dict) or "name" not in arg or "value" not in arg:
                raise ValueError(f"OliveTin Action: arguments must have name and value. Ignoring for argument '{arg}'.")
            for key, value in arg.items():
                try:
                    value = str(value)
                except ValueError:
                    raise ValueError(f"OliveTin Action: arguments value must be a string. Ignoring. {key}: {value}")
                arg[key] = value
            filtered_args.append(arg)
        return filtered_args


class NtfyViewAction(BaseConfigModel):
    action: Literal["view"] = "view"
    label: str
    url: str
    clear: Optional[bool] = False 

class NtfyBroadcastAction(BaseConfigModel):
    action: Literal["broadcast"] = "broadcast"
    label: str
    clear: Optional[bool] = False 

    intent: Optional[str] = None
    extras: Optional[dict] = None

class NtfyHttpAction(BaseConfigModel):
    action: Literal["http"] = "http"
    label: str
    url: str
    clear: Optional[bool] = False 

    method: Optional[str] = None
    headers: Optional[dict] = None
    body: Optional[str] = None

NtfyAction = Annotated[
    Union[NtfyViewAction, NtfyHttpAction, NtfyBroadcastAction],
    Field(discriminator="action")
]

class DefaultsConfig(BaseConfigModel):
    ntfy_tags: Optional[str] = None
    ntfy_topic: Optional[str] = None
    ntfy_priority: Optional[Union[str, int]] = None
    ntfy_url: Optional[str] = None
    ntfy_token: Optional[SecretStr] = None
    ntfy_username: Optional[str] = None
    ntfy_password: Optional[SecretStr] = None
    ntfy_icon: Optional[str] = None
    ntfy_click: Optional[str] = None
    ntfy_markdown: Optional[bool] = None
    ntfy_actions: Optional[List[NtfyAction]] = None
    ntfy_headers: Optional[dict] = None

    apprise_url: Optional[SecretStr] = None
    
    webhook_url: Optional[str] = None
    webhook_headers: Optional[dict] = None

    attach_logfile: bool = False
    notification_cooldown: int = 5
    title_template: Optional[str] = None
    message_template: Optional[str] = None
    action_cooldown: Optional[int] = 60
    attachment_lines: int = 20
    hide_full_regex: Optional[bool] = False
    regex_case_sensitive: bool = True
    ignore_keywords: Optional[List[Union[str, IgnoreKeywordItem]]] = None
    disable_notifications: Optional[bool] = None
    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("action_cooldown", mode="before")
    def validate_action_cooldown(cls, v):
        """Validate action cooldown with minimum value enforcement."""
        return validate_action_cooldown(v)

    @field_validator("ntfy_actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v   



class KeywordItemBase(DefaultsConfig):
    """Base class for keyword items with common fields for actions and templates."""
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action")
    def validate_container_action(cls, v):
        """Validate container action against available actions enum."""
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            raise ValueError(f"Error in config in field 'container_action': Invalid container action ('{v}')")
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class RegexItem(KeywordItemBase):
    """
    Model for a regex-based keyword with optional settings.
    Template allows for notification formatting using named capturing groups.
    """
    kind: Literal["regex"] = Field("regex", repr=False, exclude=True)
    regex: str

class KeywordItem(KeywordItemBase):
    """
    Model for a string-based keyword with optional settings.
    """
    kind: Literal["keyword"] = Field("keyword", repr=False, exclude=True)
    keyword: str

class KeywordGroup(KeywordItemBase):
    """
    Model for a group of keywords that must all be present in a log line.
    All keywords in the group must match for the group to trigger.
    """
    kind: Literal["keyword_group"] = Field("keyword_group", repr=False, exclude=True)
    keyword_group: List[Union[str, KeywordItem, RegexItem]] = []

class KeywordBase(BaseConfigModel):
    """Base class for keyword configuration with validation logic."""
    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER

    # keywords: List[Union[str, KeywordItem, RegexItem, KeywordGroup]] = []
    keywords: List[
        Union[
            str,
            Annotated[
                Union[KeywordItem, RegexItem, KeywordGroup],
                Field(discriminator="kind")
            ]
        ]
    ] = []
    @model_validator(mode="before")
    def validate_keywords(cls, data: dict) -> dict:
        """
        Convert integer keywords to strings and filter out misconfigured entries before validation.
        Also validates actions and regex patterns.
        """
        if "keywords" in data and isinstance(data["keywords"], list):
            converted = []
            for item in data["keywords"]:
                if isinstance(item, dict):
                    keys = list(item.keys())
                    # Validate required keys
                    if "keyword" in item:
                        item["kind"] = "keyword"
                    elif "regex" in item:
                        if not validate_regex(item["regex"]):
                            raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: Invalid regex.")
                        item["kind"] = "regex"
                    elif "keyword_group" in item:
                        if not isinstance(item["keyword_group"], list):
                            raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword_group' as a list.")
                        item["kind"] = "keyword_group"
                    else:
                        raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword', 'regex' or 'keyword_group' as a key.")
                    # Validate and convert fields
                    for key in keys:
                        if key == "container_action":
                            valid, error = is_valid_container_action(item[key], monitor_type=cls._MONITOR_TYPE)
                            if not valid:
                                raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: Invalid action: {error}")
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
                    converted.append(item)
                else:
                    try:
                        converted.append(str(item))
                    except ValueError:
                        raise ValueError(f"Error in config in field 'keywords': '{item}' is not a string.")
            data["keywords"] = converted
        return data

class ContainerEventConfig(DefaultsConfig):
    event: Literal[*SUPPORTED_CONTAINER_EVENTS] # type: ignore
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action")
    def validate_container_action(cls, v):
        """Validate container action against available actions enum."""
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            raise ValueError(f"Error in config in field 'container_events': Invalid container action ('{v}'). Must be one of {SUPPORTED_CONTAINER_ACTIONS}")
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class ContainerEventBase(BaseConfigModel):
    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER

    container_events: Optional[List[ContainerEventConfig]] = None

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        if "container_events" in data and isinstance(data["container_events"], list):
            converted = []
            for item in data["container_events"]:
                if isinstance(item, str):
                    if item.strip() not in SUPPORTED_CONTAINER_EVENTS:
                        raise ValueError(f"Error in config in field 'container_events': '{item}' is not a valid event. Valid events are: {SUPPORTED_CONTAINER_EVENTS}")
                    converted.append({
                        "event": item.strip(),
                    })
                elif isinstance(item, dict):
                    for key in item.keys():
                        if key == "container_action":
                            valid, error = is_valid_container_action(item[key], monitor_type=cls._MONITOR_TYPE)
                            if not valid:
                                raise ValueError(f"Error in config in field 'container_events': Invalid action ('{item[key]}') for event '{item['event']}': {error}")
                            item[key] = valid
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
                    converted.append(item)
                else:
                    raise ValueError(f"Error in config in field 'container_events': '{item}' is not a string or dict.")
            data["container_events"] = converted
        return data


class ScopeConfig(BaseConfigModel):
    hosts: Optional[List[str]] = None

# ================================================
# Container Config Classes
# ================================================
class ContainerNeverMonitor(BaseConfigModel):
    container_names: Optional[List[str]] = None

class DockerPolicyBase(KeywordBase, ContainerEventBase, DefaultsConfig):
    id: Optional[str] = None # TODO: auto-generated if missing
    enabled: bool = True
    scope: Optional[ScopeConfig] = None
    # All modular settings are inherited from DefaultsConfig
    # keywords and container_events are inherited from KeywordBase and ContainerEventBase

class ContainerMatchCriteria(BaseConfigModel):
    container_names: Optional[List[str]] = None

class ContainerMatch(BaseConfigModel):
    include: Optional[ContainerMatchCriteria] = None
    exclude: Optional[ContainerMatchCriteria] = None


# Container policy
class ContainerPolicy(DockerPolicyBase):
    container_name: Optional[str] = None # shorthand
    match: Optional[ContainerMatch] = None

    @model_validator(mode="before")                                   
    def validate_shorthand_or_match(cls, data: dict) -> dict:         
        if isinstance(data, dict):                                    
            has_shorthand = data.get("container_name") is not None    
            has_match = data.get("match") is not None                 
            if has_shorthand and has_match:                           
                raise ValueError(                                     
                    "Cannot use both 'container_name' shorthand and 'match' block. "                                                  
                    "Use one or the other."                           
                )                                                     
        return data    


class ContainerSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[ContainerNeverMonitor] = None
    defaults: Optional[DefaultsConfig] = None # source-level defaults
    policies: Optional[List[ContainerPolicy]] = None
    overlays: Optional[List[ContainerPolicy]] = None
    # container_events inherited from ContainerEventBase
    # keywords inherited from KeywordBase

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_if_missing(data)

def generate_id_if_missing(data: Any) -> Any:
    if not data:
        return data
    if isinstance(data, dict):
        for idx, policy in enumerate(data.get("policies", [])):
            if policy.get("id") is None:
                policy["id"] = f"policy_{idx}"
    return data


# ================================================
# Swarm Config Classes
# ================================================
class SwarmNeverMonitor(BaseConfigModel):
    stack_names: Optional[List[str]] = None
    service_names: Optional[List[str]] = None

class SwarmMatchCriteria(BaseConfigModel):
    stack_names: Optional[List[str]] = None
    service_names: Optional[List[str]] = None

class SwarmMatch(BaseConfigModel):
    include: Optional[SwarmMatchCriteria] = None
    exclude: Optional[SwarmMatchCriteria] = None

class SwarmPolicy(DockerPolicyBase):
    stack_name: Optional[str] = None # shorthand
    service_name: Optional[str] = None # shorthand
    match: Optional[SwarmMatch] = None

    @model_validator(mode="before")                                   
    def validate_shorthand_or_match(cls, data: dict) -> dict:         
        if isinstance(data, dict):                                    
            has_shorthand = data.get("stack_name") is not None or data.get("service_name") is not None    
            has_match = data.get("match") is not None                 
            if has_shorthand and has_match:                           
                raise ValueError(                                     
                    "Cannot use both 'stack_name' or 'service_name' shorthand and 'match' block. "                                                  
                    "Use one or the other."                           
                )                                                     
        return data    


class SwarmSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.SWARM

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[SwarmNeverMonitor] = None
    defaults: Optional[DefaultsConfig] = None # source-level defaults
    policies: Optional[List[SwarmPolicy]] = None
    overlays: Optional[List[SwarmPolicy]] = None
    # container_events inherited from ContainerEventBase
    # keywords inherited from KeywordBase

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_if_missing(data)

class NtfyConfig(BaseConfigModel):
    url: str 
    topic: str 
    token: Optional[SecretStr] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    priority: Optional[Union[str, int]] = 3
    tags: Optional[str] = "kite,mag"
    icon: Optional[str] = None
    click: Optional[str] = None
    markdown: Optional[bool] = None
    actions: Optional[List[NtfyAction]] = None
    headers: Optional[dict] = None

class AppriseConfig(BaseConfigModel):  
    url: SecretStr 

class WebhookConfig(BaseConfigModel):
    url: str
    headers: Optional[dict] = None

class NotificationsConfig(BaseConfigModel):
    """Configuration for all notification services."""
    ntfy: Optional[NtfyConfig] = None
    apprise: Optional[AppriseConfig] = None
    webhook: Optional[WebhookConfig] = None

class SettingsConfig(BaseConfigModel):    
    """
    Application-wide settings.
    """
    log_level: str = "INFO"
    multi_line_entries: bool = True
    disable_start_message: bool = False
    disable_shutdown_message: bool = False
    disable_config_reload_message: bool = False
    disable_monitor_event_message: bool = False 
    compact_summary_message: bool = False
    reload_config: bool = True

class GlobalConfigV2(BaseModel):
    model_config = ConfigDict(extra="ignore") # TODO: keep ignore here?

    # version: Literal[2] = 2 # TODO: force user setting version or not?
    defaults: Optional[DefaultsConfig] = DefaultsConfig()
    containers: Optional[ContainerSourceConfig] = None
    swarm_services: Optional[SwarmSourceConfig] = None
    notifications: Optional[NotificationsConfig] = None
    settings: Optional[SettingsConfig] = SettingsConfig()


def validate_regex(v):
    """
    Validate a regex pattern by attempting to compile it.
    """
    try:
        re.compile(v)
    except re.error as e:
        return False 
    return True


def get_kw_or_rgx(item):
    """
    Extract the keyword, regex, or keyword_group from a config item for error reporting.
    """
    if isinstance(item, dict):
        if "keyword" in item:
            return f"keyword: '{item['keyword']}'"
        elif "regex" in item:
            return f"regex: '{item['regex']}'"
        elif "keyword_group" in item:
            return f"keyword_group: '{item['keyword_group']}'"
    return "unknown"

def is_valid_container_action(value, monitor_type: MonitorType) -> tuple[bool, str]:
    if monitor_type == MonitorType.SWARM:
        if len(value.split('@')) < 2:
            return False, "container_actions on swarm services are not allowed. Action must be in the format 'action@container_name'"
    elif monitor_type == MonitorType.CONTAINER:
        pass
    else:
        return False, "Container Action not allowed for monitor type: " + monitor_type.value
    if not isinstance(value, str):
        return False, "container action must be a string"
    if not 0 < len(value.split('@')) < 3:
        return False, "container action must be in the format 'action@hostname'"
    if value.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
        return False, "container action must be one of " + ", ".join(SUPPORTED_CONTAINER_ACTIONS)

    return True, ""


def validate_and_filter_olivetin_actions(data: dict) -> dict:
    if not data:
        return data
    if "olivetin_actions" in data and isinstance(data["olivetin_actions"], list):
        for action in data["olivetin_actions"]:
            if not isinstance(action, dict) or "id" not in action:
                raise ValueError("OliveTin Action: Must be a dictionary with an 'id' key.")
            action["id"] = str(action["id"])
    if data.get("olivetin_action_id"):
        data.setdefault("olivetin_actions", []).append({
            "id": data["olivetin_action_id"],
        })
        data.pop("olivetin_action_id")
    return data


def validate_ntfy_actions(actions: list[Any]) -> list[Any]:       
    if len(actions) > 3:                                          
        raise ValueError(f"Ntfy actions: maximum 3 allowed, got {len(actions)}")                                                  
    return actions                                                