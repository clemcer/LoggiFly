from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    ValidationError,
    Field,
)
from typing import Literal
from enum import Enum
from constants import SUPPORTED_CONTAINER_ACTIONS, SUPPORTED_EVENTS
from typing import List, Optional, Union, ClassVar, Annotated, Any
import logging
import re
import copy

class BaseConfigModel(BaseModel):
    """Base configuration model with common Pydantic settings."""
    model_config = ConfigDict(
        extra="ignore",
        validate_default=True,
        use_enum_values=True,
        from_attributes=False,
        arbitrary_types_allowed=False,
    )


class ExcludedKeywords(BaseConfigModel):
    """Model for excluded keyword definitions that can be keyword-based or regex-based."""
    keyword: Optional[str] = None
    regex: Optional[str] = None

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
class Settings(BaseConfigModel):    
    """
    Application-wide settings.
    """
    log_level: str = "INFO"
    multi_line_entries: bool = True
    disable_start_message: bool = False
    disable_shutdown_message: bool = False
    disable_config_reload_message: bool = False
    disable_monitor_event_message: bool = False # previously: disable_container_event_message
    compact_summary_message: bool = False
    reload_config: bool = True
    monitor_all_containers: bool = False
    excluded_containers: Optional[List[str]] = None
    monitor_all_swarm_services: bool = False
    excluded_swarm_services: Optional[List[str]] = None

    # modular settings:
    attach_logfile: bool = False
    notification_cooldown: int = 5
    title_template: Optional[str] = None # previously: notification_title
    message_template: Optional[str] = None # previously: json_template and template
    action_cooldown: Optional[int] = 300
    attachment_lines: int = 20
    hide_regex_in_title: Optional[bool] = False
    excluded_keywords: Optional[List[Union[str, ExcludedKeywords]]] = None
    disable_notifications: Optional[bool] = None
    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("action_cooldown", mode="before")
    def validate_action_cooldown(cls, v):
        """Validate action cooldown with minimum value enforcement."""
        return validate_action_cooldown(v)


class ModularSettings(BaseConfigModel):
    """
    Optional settings that can be overridden per keyword or container.
    These settings allow fine-grained control at different configuration levels.
    """
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

    attachment_lines: Optional[int] = None
    notification_cooldown: Optional[int] = None
    title_template: Optional[str] = None
    message_template: Optional[str] = None
    action_cooldown: Optional[int] = None
    attach_logfile: Optional[bool] = None
    excluded_keywords: Optional[List[Union[str, ExcludedKeywords]]] = None
    hide_regex_in_title: Optional[bool] = None
    disable_notifications: Optional[bool] = None

    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)
        
    @field_validator("ntfy_actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v   

    @field_validator("action_cooldown", mode="before")
    def validate_action_cooldown(cls, v):
        if v is None:
            return None
        return validate_action_cooldown(v)

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
            logging.warning(f"OliveTin Action: arguments must be a list. Ignoring for argument(s) '{v}'.")
            return None
        filtered_args = []
        for arg in v:
            if not isinstance(arg, dict) or "name" not in arg or "value" not in arg:
                logging.warning(f"OliveTin Action: arguments must have name and value. Ignoring for argument '{arg}'.")
                continue
            for key, value in arg.items():
                try:
                    value = str(value)
                except ValueError:
                    logging.warning(f"OliveTin Action: arguments value must be a string. Ignoring. {key}: {value}")
                    continue
                arg[key] = value
            filtered_args.append(arg)
        return filtered_args


class KeywordItemBase(ModularSettings):
    """Base class for keyword items with common fields for actions and templates."""
    # json_template: Optional[str] = None # legacy
    action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("action")
    def validate_action(cls, v):
        """Validate action against available actions enum."""
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            return None
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
    regex: str
    # template: Optional[str] = None # legacy

class KeywordItem(KeywordItemBase):
    """
    Model for a string-based keyword with optional settings.
    """
    keyword: str


class KeywordGroup(KeywordItemBase):
    """
    Model for a group of keywords that must all be present in a log line.
    All keywords in the group must match for the group to trigger.
    """
    keyword_group: List[Union[str, KeywordItem, RegexItem]] = []


class KeywordBase(BaseModel):
    """Base class for keyword configuration with validation logic."""
    _DISALLOW_SELF_CONTAINER_ACTION: ClassVar[bool] = False

    keywords: List[Union[str, KeywordItem, RegexItem, KeywordGroup]] = []

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
                    if "keyword" not in item and "regex" not in item and "keyword_group" not in item:
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword', 'regex' or 'keyword_group' as a key.")
                        continue
                    elif "keyword_group" in item and not isinstance(item["keyword_group"], list):
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword_group' as a list.")
                        continue
                    elif "regex" in item and not validate_regex(item["regex"]):
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: Invalid regex.")
                        continue
                    # Validate and convert fields
                    for key in keys:
                        if key == "action":
                            valid, error = is_valid_container_action(item["action"], disallow_self_action=cls._DISALLOW_SELF_CONTAINER_ACTION)
                            if not valid:
                                logging.warning(f"Error in config in field {get_kw_or_rgx(item)}: Invalid action: {error}")
                                item["action"] = None
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
                    converted.append(item)
                else:
                    try:
                        converted.append(str(item))
                    except ValueError:
                        logging.warning(f"Ignoring unexpected Error in config in field 'keywords': '{item}'.")
                        continue
            data["keywords"] = converted
        return data


class ContainerEventConfig(ModularSettings):
    event: Literal[*SUPPORTED_EVENTS] # type: ignore
    action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data

    @field_validator("action")
    def validate_action(cls, v):
        """Validate action against available actions enum."""
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            return None
        return v    
    
class ContainerEventBase(BaseConfigModel):
    container_events: Optional[List[ContainerEventConfig]] = None
    _DISALLOW_SELF_CONTAINER_ACTION: ClassVar[bool] = False

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        if "container_events" in data and isinstance(data["container_events"], list):
            converted = []
            for item in data["container_events"]:
                if isinstance(item, str):
                    if item.strip() not in SUPPORTED_EVENTS:
                        logging.warning(f"Ignoring Error in config in field 'container_events': '{item}' is not a valid event. Valid events are: {SUPPORTED_EVENTS}")
                        continue
                    converted.append({
                        "event": item.strip(),
                    })
                elif isinstance(item, dict):
                    if not item.get("event"):
                        logging.warning(f"Ignoring Error in config in field 'container_events': '{item}' is not a valid event. Valid events are: {SUPPORTED_EVENTS}")
                        continue
                    if item["event"] not in SUPPORTED_EVENTS:
                        logging.warning(f"Ignoring Error in config in field 'container_events': '{item['event']}' is not a valid event. Valid events are: {SUPPORTED_EVENTS}")
                        continue
                    for key in item.keys():
                        if key == "action":
                            valid, error = is_valid_container_action(item["action"], disallow_self_action=cls._DISALLOW_SELF_CONTAINER_ACTION)
                            if not valid:
                                logging.warning(f"Error in config in field 'container_events': Invalid action ('{item['action']}') for event '{item['event']}': {error}")
                                item["action"] = None
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
                    converted.append(item)
                else:
                    logging.warning(f"Ignoring Error in config in field 'container_events': '{item}' is not a string or dict.")
                    continue
            data["container_events"] = converted
        return data

class ContainerConfig(KeywordBase, ContainerEventBase, ModularSettings):    
    """
    Model for per-container configuration, including keywords and setting overrides.
    Allows targeting specific hosts when multiple Docker hosts are configured.
    """
    hosts: Optional[str] = None
    
    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)

class SwarmServiceConfig(KeywordBase, ContainerEventBase, ModularSettings):
    """
    Model for per-swarm service configuration, inheriting from ContainerConfig.
    Actions on swarm services are not allowed.
    """
    _DISALLOW_SELF_CONTAINER_ACTION: ClassVar[bool] = True
    hosts: Optional[str] = None
class GlobalKeywords(BaseConfigModel, KeywordBase):
    """Global keyword configuration that applies to all monitored containers."""
    pass

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

    @field_validator("priority", mode="before")
    def validate_priority(cls, v):
        """Validate ntfy priority value."""
        return validate_priority(v)

    @field_validator("actions", mode="before")
    def validate_actions(cls, v):
        if not v:
            return v
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        logging.warning("Ntfy actions: expected a list, got %r – ignoring", v)
        return None


class AppriseConfig(BaseConfigModel):  
    url: SecretStr 


class WebhookConfig(BaseConfigModel):
    url: str
    headers: Optional[dict]


class NotificationsConfig(BaseConfigModel):
    """Configuration for all notification services."""
    ntfy: Optional[NtfyConfig] = None
    apprise: Optional[AppriseConfig] = None
    webhook: Optional[WebhookConfig] = None

    @model_validator(mode="after")
    def check_at_least_one(self) -> "NotificationsConfig":
        """Warn if no notification services are configured."""
        if self.ntfy is None and self.apprise is None and self.webhook is None:
            logging.warning("You haven't configured any notification services. Notifications will not be sent.")
        return self


class HostConfig(BaseConfigModel):
    monitor_all_containers: Optional[bool] = None
    excluded_containers: Optional[List[str]] = None
    containers: dict[str, ContainerConfig] | None = None

class GlobalConfig(BaseConfigModel):
    """Root configuration model for the application."""
    hosts: dict[str, HostConfig] | None = None
    containers: dict[str, ContainerConfig] | None = None
    swarm_services: dict[str, SwarmServiceConfig] | None = None
    global_keywords: GlobalKeywords
    notifications: NotificationsConfig
    settings: Settings

    @model_validator(mode="before")
    def transform_legacy_format(cls, values):
        """Migrate legacy list-based container definitions to dictionary format."""

        # Helper function to process a container object
        def process_container_dict(container_dict):
            """Convert list format to dict and handle None values."""
            if not isinstance(container_dict, dict):
                return
            for container_name in list(container_dict.keys()):
                container_config = container_dict[container_name]
                if isinstance(container_config, list):
                    # Legacy format: direct keywords list
                    container_dict[container_name] = {"keywords": container_config}
                elif container_config is None:
                    # None value: create empty keywords list
                    container_dict[container_name] = {"keywords": []}

        # Process top-level containers
        if values.get("containers"):
            if isinstance(values["containers"], list):
                # Convert list of container names to dict
                values["containers"] = {name: {"keywords": []} for name in values["containers"]}
            else:
                process_container_dict(values["containers"])

        # Process top-level swarm_services
        if values.get("swarm_services"):
            if isinstance(values["swarm_services"], list):
                # Convert list of service names to dict
                values["swarm_services"] = {name: {"keywords": []} for name in values["swarm_services"]}
            else:
                process_container_dict(values["swarm_services"])

        # Process host-specific containers
        if values.get("hosts"):
            for host_name, host_config in values["hosts"].items():
                if host_config and host_config.get("containers"):
                    if isinstance(host_config["containers"], list):
                        # Convert list of container names to dict
                        host_config["containers"] = {name: {"keywords": []} for name in host_config["containers"]}
                    else:
                        process_container_dict(host_config["containers"])

        return values    

    @model_validator(mode="after")
    def check_at_least_one(self) -> "GlobalConfig":
        """Ensure at least one container or swarm service and at least one keyword is configured."""
        configs = [self.containers, self.swarm_services]
        if self.hosts:
            configs.extend([h.containers for h in self.hosts.values() if h.containers])
        if not any(configs):
            logging.warning("You haven't configured any containers or swarm services via a config file or environment variables. Ignore this warning if you are using Docker labels to configure everything.")
        all_keywords = copy.deepcopy(self.global_keywords.keywords)
        if not all_keywords:
            for config in configs:
                if config:
                    for c in config.values():
                        all_keywords.extend(c.keywords)
                if all_keywords:
                    break
        if not all_keywords:
            logging.warning("No keywords configured via a config file or environment variables. Ignore this warning if you are using Docker labels to configure everything.")
        return self


def validate_action_cooldown(v):
    """
    Validate action cooldown value with minimum threshold enforcement.
    """
    if v is None:
        return None
    try:
        v = int(v)
    except ValueError:
        return None
    if v < 10:
        logging.warning("Action cooldown must be at least 10 seconds. Setting to 10 seconds")
        return 10
    return v

def is_valid_container_action(value, disallow_self_action: bool = False) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, "action must be a string"
    if not 0 < len(value.split('@')) < 3:
        return False, "action must be in the format 'action@hostname'"
    if value.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
        return False, "action must be one of " + ", ".join(SUPPORTED_CONTAINER_ACTIONS)
    if disallow_self_action and len(value.split('@')) < 2:
        return False, "actions on swarm containers/services are not allowed"
    return True, ""

def validate_priority(v):
    """
    Validate and normalize the ntfy priority value. 
    """
    if isinstance(v, str):
        try:
            v = int(v)
        except ValueError:
            pass
    if isinstance(v, int):
        if not 1 <= int(v) <= 5:
            logging.warning(f"Error in config for ntfy.priority. Must be between 1-5, '{v}' is not allowed. Using default: '3'")
            return 3
    if isinstance(v, str):
        options = ["max", "urgent", "high", "default", "low", "min"]
        if v not in options:
            logging.warning(f"Error in config for ntfy.priority:'{v}'. Only 'max', 'urgent', 'high', 'default', 'low', 'min' are allowed. Using default: '3'")
            return 3
    return v

def validate_and_filter_olivetin_actions(data: dict) -> dict:
    if not data:
        return data
    if "olivetin_actions" in data and isinstance(data["olivetin_actions"], list):
        for action in data["olivetin_actions"]:
            if not isinstance(action, dict) or "id" not in action:
                logging.warning("OliveTin Action: id must be a string. Ignoring.")
                continue
            action["id"] = str(action["id"])
    if data.get("olivetin_action_id"):
        data.setdefault("olivetin_actions", []).append({
            "id": data["olivetin_action_id"],
        })
        data.pop("olivetin_action_id")
    return data

def validate_regex(v):
    """
    Validate a regex pattern by attempting to compile it.
    """
    try:
        re.compile(v)
    except re.error as e:
        logging.warning(f"Error in config for regex: '{v}'. Invalid regex. {e}")
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

def validate_container_events(v):
    if not v:
        return v
    converted = []
    if v and isinstance(v, list):
        for event in v:
            if not isinstance(event, dict) or "event" not in event:
                logging.warning(f"Ignoring Error in config in field 'container_events': '{event}' is not a dict or does not have an 'event' key.")
                continue
            if event["event"] not in SUPPORTED_EVENTS:
                logging.warning(f"Ignoring Error in config in field 'container_events': '{event['event']}' is not a valid event. Valid events are: {SUPPORTED_EVENTS}")
                continue
            converted.append(event)
    else:
        logging.warning("Container Events: expected a list, got %r – ignoring", v)
        return None
    return converted


def validate_ntfy_actions(actions: list[Any]) -> list[dict]:
    possible_actions = ["http", "broadcast", "view"]
    filtered_actions = []
    for idx, raw in enumerate(actions, 1):
        if isinstance(raw, (NtfyViewAction, NtfyHttpAction, NtfyBroadcastAction)):
            logging.debug(f"Ntfy Action: {raw}")
            if len(filtered_actions) >= 3:
                logging.warning(f"Ntfy Action: You can only have up to 3 actions. Ignoring additional actions: {actions[idx-1:]}")
                break
            filtered_actions.append(raw.model_dump(exclude_none=True))
            continue
        if not isinstance(raw, dict):
            logging.warning(f"Ntfy Action: action must be a dictionary. Ignoring action '{raw}'.")
            continue
        action_type = raw.get("action")
        if not action_type or action_type not in possible_actions:
            logging.warning(f"Ntfy Action: action must be one of {possible_actions}. Ignoring action '{raw}'.")
            continue
        if not raw.get("label"):
            logging.warning(f"Ntfy Action: label is required. Ignoring action '{raw}'.")
            continue
        if action_type in ["http", "view"] and not raw.get("url"):
            logging.warning(f"Ntfy Action: url is required for action '{raw['action']}'. Ignoring action '{raw}'.")
            continue
        if action_type == "broadcast" and not raw.get("intent"):
            logging.warning(f"Ntfy Action: intent is required for action '{raw['action']}'. Ignoring action '{raw}'.")
            continue
        if len(filtered_actions) >= 3:
            logging.warning(f"Ntfy Action: You can only have up to 3 actions. Ignoring additional actions: {actions[idx-1:]}")
            break
        filtered_actions.append(raw)
    return filtered_actions