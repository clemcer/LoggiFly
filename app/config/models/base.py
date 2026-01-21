from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    Field,
)
from typing import Literal, Optional, List, Union, Annotated, ClassVar
from constants import MonitorType, SUPPORTED_CONTAINER_ACTIONS
from config.helpers import (
    validate_action_cooldown,
    validate_ntfy_actions,
    validate_and_filter_olivetin_actions,
    validate_keywords,
    validate_simple_keywords,
    validate_olivetin_arguments,
    handle_error,
    validate_ntfy_priority,
    strict_config_validation,
)

class BaseConfigModel(BaseModel):
    """Base configuration model with common Pydantic settings."""
    model_config = ConfigDict(
        extra="forbid" if strict_config_validation() else "ignore", # TODO: change later, possibly configurable by env
        validate_default=True,
        use_enum_values=True,
        from_attributes=False,
        arbitrary_types_allowed=False,
    )


# ================================================
# Settings Config Classes
# ================================================

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

# ================================================ 
# Misc Config Models (shared between models)
# ================================================

class SimpleKeywordItem(BaseConfigModel):
    keyword: Optional[str] = None
    regex: Optional[str] = None

    @model_validator(mode="before")
    def validate_simple_keyword_item(cls, data: dict) -> dict:
        """
        Invariant check: ensures exactly one of keyword/regex is set.  
        Pre-validation in validate_simple_keywords() should filter out invalid items before they reach here.
        """
        if not data.get("keyword") and not data.get("regex"):
            raise ValueError(f"You have to set 'keyword' or 'regex' as a key.")
        if data.get("keyword") and data.get("regex"):
            raise ValueError(f"You can only set 'keyword' or 'regex', not both.")
        return data

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

# ================================================
# Defaults Config Model
# ================================================
                                                                     
class EmptyDefaultsConfig(BaseConfigModel):
    ignore_keywords: Optional[List[SimpleKeywordItem]] = None
    title_template: Optional[str] = None
    message_template: Optional[str] = None
    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

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

    @field_validator("ntfy_actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v   

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_ntfy_priority(v)


    @field_validator("ignore_keywords", mode="before")
    def validate_ignore_keywords(cls, v):
        if v and isinstance(v, list):
            v = validate_simple_keywords(v, "ignore_keywords")
        return v


class ActionCooldownMixin:                                         
    @field_validator("action_cooldown", mode="before")             
    def validate_action_cooldown(cls, v):                          
        return validate_action_cooldown(v)                         

class ModularDefaultsConfig(EmptyDefaultsConfig, ActionCooldownMixin):

    attach_logfile: Optional[bool] = None
    notification_cooldown: Optional[int] = None
    action_cooldown: Optional[int] = None
    attachment_lines: Optional[int] = None
    hide_full_regex: Optional[bool] = None
    regex_case_sensitive: Optional[bool] = None
    disable_notifications: Optional[bool] = None

class RootDefaultsConfig(EmptyDefaultsConfig, ActionCooldownMixin):
    attach_logfile: bool = False
    notification_cooldown: int = 5
    action_cooldown: Optional[int] = 60
    attachment_lines: int = 20
    hide_full_regex: Optional[bool] = False
    regex_case_sensitive: bool = True
    disable_notifications: Optional[bool] = False


# ================================================
# Notifications Config Models
# ================================================

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
    def validate_ntfy_priority(cls, v):
        return validate_ntfy_priority(v)

    @field_validator("actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v

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


# ================================================
# Keyword Config Models
# ================================================

class OliveTinArgument(BaseConfigModel):
    name: str
    value: str

class OliveTinAction(BaseConfigModel):
    id: str
    arguments: Optional[List[OliveTinArgument]] = None

    @field_validator("arguments", mode="before")
    def validate_olivetin_arguments(cls, v):
        if v and isinstance(v, list):
            return validate_olivetin_arguments(v)
        return v


class KeywordActionsBase(ModularDefaultsConfig):
    """Base class for keyword items with common fields for actions and templates."""
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action")
    def validate_container_action(cls, v):
        """
        Last defense container action validation (ideally isn't needed) to make sure no invalid action is set.
        MonitorType specific validation is done in the instantiating class that has the cls._MONITOR_TYPE variable context.
        Raises ValueError if the container action is invalid (also in strict mode)
        """
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            raise ValueError(f"Error in config in field 'container_action': Invalid container action ('{v}')")
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class RegexItemBase(KeywordActionsBase):
    """
    Model for a regex-based keyword with optional settings.
    Template allows for notification formatting using named capturing groups.
    """
    kind: Literal["regex"] = Field("regex", repr=False, exclude=True)
    regex: str


class KeywordItemBase(KeywordActionsBase):
    """
    Model for a string-based keyword with optional settings.
    """
    kind: Literal["keyword"] = Field("keyword", repr=False, exclude=True)
    keyword: str

class KeywordGroupBase(KeywordActionsBase):
    """
    Model for a group of keywords that must all be present in a log line.
    All keywords in the group must match for the group to trigger.
    """
    kind: Literal["keyword_group"] = Field("keyword_group", repr=False, exclude=True)
    keyword_group: List[SimpleKeywordItem]

    @field_validator("keyword_group", mode="before")
    def validate_keyword_group(cls, v):
        if v and isinstance(v, list):
            v = validate_simple_keywords(v, "keyword_group")
        return v

class KeywordBase(BaseConfigModel):
    """Base class for keyword configuration with validation logic."""
    _MONITOR_TYPE: ClassVar[MonitorType | None] = None

    keywords: List[
        Annotated[
            KeywordItemBase | RegexItemBase | KeywordGroupBase,
            Field(discriminator="kind")
        ]
    ] = []
    @model_validator(mode="before")
    def validate_keywords(cls, data: dict) -> dict:
        """
        Convert integer keywords to strings and filter out misconfigured entries before validation.
        Also validates container actions and regex patterns.
        container_actions are validated here because the cls._MONITOR_TYPE variable from the instantiating class is used.
        """
        assert cls._MONITOR_TYPE is not None, "Internal Error: cls._MONITOR_TYPE is not set in instantiating class"
        if "keywords" in data and isinstance(data["keywords"], list):
            data["keywords"] = validate_keywords(data["keywords"], cls._MONITOR_TYPE)
        return data