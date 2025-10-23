from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    ValidationError,
)
from enum import Enum
from constants import Actions
from typing import List, Optional, Union, ClassVar, Annotated
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


class Settings(BaseConfigModel):    
    """
    Application-wide settings.
    """
    log_level: str = "INFO"
    multi_line_entries: bool = True
    disable_start_message: bool = False
    disable_shutdown_message: bool = False
    disable_config_reload_message: bool = False
    disable_container_event_message: bool = False
    compact_summary_message: bool = False
    reload_config: bool = True
    monitor_all_containers: bool = False
    excluded_containers: Optional[List[str]] = None
    monitor_all_swarm_services: bool = False
    excluded_swarm_services: Optional[List[str]] = None

    # modular settings:
    attach_logfile: bool = False
    notification_cooldown: int = 5
    notification_title: str = "default"
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
    apprise_url: Optional[SecretStr] = None
    webhook_url: Optional[str] = None
    webhook_headers: Optional[dict] = None

    attachment_lines: Optional[int] = None
    notification_cooldown: Optional[int] = None
    notification_title: Optional[str] = None
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
    json_template: Optional[str] = None
    action: Optional[str] = None
    # olivetin_action_id: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("action")
    def validate_action(cls, v):
        """Validate action against available actions enum."""
        if v and not any(a.value == v.split('@')[0] for a in Actions):
            return None
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
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

class RegexItem(KeywordItemBase):
    """
    Model for a regex-based keyword with optional settings.
    Template allows for notification formatting using named capturing groups.
    """
    regex: str
    template: Optional[str] = None


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
    _DISALLOW_ACTION: ClassVar[bool] = False

    keywords: List[Union[str, KeywordItem, RegexItem, KeywordGroup]] = []

    @model_validator(mode="before")
    def int_to_string(cls, data: dict) -> dict:
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
                            if (not isinstance(item["action"], str) 
                            or not 0 < len(item["action"].split('@')) < 3 
                            or not any(action.value in item["action"].split('@')[0] for action in Actions)):
                                logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: Invalid action: '{item['action']}'.")
                                item["action"] = None
                            elif cls._DISALLOW_ACTION and len(item["action"].split('@')) < 2:
                                logging.warning(f"Actions on swarm containers/services are not allowed. Removing action '{item['action']}' for {get_kw_or_rgx(item)}")
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


class ContainerConfig(KeywordBase, ModularSettings):    
    """
    Model for per-container configuration, including keywords and setting overrides.
    Allows targeting specific hosts when multiple Docker hosts are configured.
    """
    hosts: Optional[str] = None

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)


class SwarmServiceConfig(KeywordBase, ModularSettings):
    """
    Model for per-swarm service configuration, inheriting from ContainerConfig.
    Actions on swarm services are not allowed.
    """
    _DISALLOW_ACTION: ClassVar[bool] = True
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

    @field_validator("priority", mode="before")
    def validate_priority(cls, v):
        """Validate ntfy priority value."""
        return validate_priority(v)


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
    monitor_all_containers: bool = False
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
        to_convert = [
            values.get("containers"), values.get("swarm_services"),
            ] + [values["hosts"].get(host, {}).get("containers") for host in values.get("hosts", {})] if values.get("hosts") else []
        for container_object in to_convert:
            if container_object is None:
                continue
            if isinstance(container_object, list):
                container_object = {name: {} for name in container_object}
            for container in container_object:
                if isinstance(container_object.get(container), list):
                    container_object[container] = {
                        "keywords": container_object[container],
                    }
                elif container_object.get(container) is None:
                    container_object[container] = {
                        "keywords": [],
                    }
        return values
    
    @model_validator(mode="after")
    def check_at_least_one(self) -> "GlobalConfig":
        """Ensure at least one container or swarm service and at least one keyword is configured."""
        configs = [self.containers, self.swarm_services] + [h.containers for h in self.hosts.values() if h.containers] if self.hosts else []
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