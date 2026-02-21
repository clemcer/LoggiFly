from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    Field,
    Discriminator,
    Tag
)
from typing import Literal, Optional, List, Union, Annotated, Dict, Any
from contextvars import ContextVar
import logging
from config.helpers import (
    validate_container_action_cooldown,
    validate_ntfy_actions,
    validate_and_filter_olivetin_actions,
    validate_keywords,
    validate_simple_keywords,
    validate_olivetin_arguments,
    validate_ntfy_priority,
    strict_config_validation,
    validate_container_action,
    discriminate_keyword_type,
    validate_trigger_on,
)

logger = logging.getLogger(__name__)

_validation_ctx: ContextVar[Dict[str, Any]] = ContextVar("_validation_ctx", default={})
SKIP_CONTAINER_ACTION_VALIDATION = "SKIP_CONTAINER_ACTION_VALIDATION"

class BaseConfigModel(BaseModel):
    """Base configuration model with common Pydantic settings."""
    model_config = ConfigDict(
        extra="forbid" if strict_config_validation() else "ignore",
        validate_default=True,
        use_enum_values=True,
        from_attributes=False,
        arbitrary_types_allowed=False,
    )

    @model_validator(mode="before")
    @classmethod
    def log_extra_fields(cls, data: Any) -> Any:
        if not strict_config_validation() and isinstance(data, dict):
            unknown = set(data.keys()) - set(cls.model_fields.keys())
            if unknown:
                f = "fields" if len(unknown) > 1 else "field"
                logger.warning(
                    f"Unknown {f} in config: {unknown}"
                )
        return data


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
class SimpleKeyword(BaseConfigModel):
    keyword: str

class SimpleRegex(BaseConfigModel):
    regex: str

SimpleKeywords = List[
    Annotated[
        Union[
            Annotated[SimpleKeyword, Tag("keyword")],
            Annotated[SimpleRegex, Tag("regex")],
        ],
    Discriminator(discriminate_keyword_type)]]

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

class NotificationDefaults(BaseConfigModel):
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

class EmptyDefaults(NotificationDefaults):
    ignore_keywords: Optional[SimpleKeywords] = None
    title_template: Optional[str] = None
    message_template: Optional[str] = None
    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("ignore_keywords", mode="before")
    def validate_ignore_keywords(cls, v):
        if v and isinstance(v, list):
            v = validate_simple_keywords(v, "ignore_keywords")
        return v


class ActionCooldownMixin:
    @field_validator("container_action_cooldown", mode="before")             
    def validate_container_action_cooldown(cls, v):                          
        return validate_container_action_cooldown(v)                         

class ModularDefaultsConfig(EmptyDefaults, ActionCooldownMixin):

    attach_logfile: Optional[bool] = None
    trigger_cooldown: Optional[int] = None
    container_action_cooldown: Optional[int] = None
    attachment_lines: Optional[int] = None
    hide_full_regex: Optional[bool] = None
    regex_case_sensitive: Optional[bool] = None
    disable_notifications: Optional[bool] = None
    merge_matches: Optional[bool] = None

class RootDefaultsConfig(EmptyDefaults, ActionCooldownMixin):
    attach_logfile: bool = False
    trigger_cooldown: int = 0
    container_action_cooldown: int = 60
    attachment_lines: int = 20
    hide_full_regex: bool = False
    regex_case_sensitive: bool = True
    disable_notifications: bool = False
    merge_matches: bool = False


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

class TriggerActions(BaseModel):
    """
    Base class for trigger actions. 
    Any class that uses this base class must inject the monitor_type into the context
    if it wants container_actions to be validated correctly. See ContainerSourceConfig for an example.
    """
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action", mode="before")
    @classmethod
    def validate_container_action(cls, v):
        if v is None or _validation_ctx.get().get(SKIP_CONTAINER_ACTION_VALIDATION):
            return v
        monitor_type = _validation_ctx.get().get("monitor_type")
        return validate_container_action(v, monitor_type)

    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        """validate olivetin actions and convert olivetin_action_id to a valid olivetin_action"""
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class TriggerOnConfig(BaseConfigModel):
    """
    Threshold-based triggering: only trigger when a keyword matches
    `count` times within `timeframe` seconds.
    """
    count: int = Field(ge=2)
    timeframe: int = Field(ge=1)
    
class TriggerOnBase(BaseConfigModel):
    trigger_on: Optional[TriggerOnConfig] = None

    @field_validator("trigger_on", mode="before")
    def validate_trigger_on(cls, v):
        return validate_trigger_on(v)

class TriggerActionsBase(ModularDefaultsConfig, TriggerActions, TriggerOnBase):
    """Base class for keyword items with common fields for actions and templates."""
    pass


class RegexItem(TriggerActionsBase):
    """
    Model for a regex-based keyword with optional settings.
    Template allows for notification formatting using named capturing groups.
    """
    regex: str


class KeywordItem(TriggerActionsBase):
    """
    Model for a string-based keyword with optional settings.
    """
    keyword: str


class AllOfKeywords(TriggerActionsBase):
    """
    Model for a list of keywords/regexes that must all be present in a log line.
    All items in the list must match for the list to trigger.
    """
    all_of: SimpleKeywords


    @field_validator("all_of", mode="before")
    def validate_all_of(cls, v):
        if v and isinstance(v, list):
            v = validate_simple_keywords(v, "all_of")
        return v

class KeywordBase(BaseConfigModel):
    """Base class for keyword configuration with validation logic."""

    keywords: List[
        Annotated[
            Union[
                Annotated[KeywordItem, Tag("keyword")], 
                Annotated[RegexItem, Tag("regex")], 
                Annotated[AllOfKeywords, Tag("all_of")]],
            Discriminator(discriminate_keyword_type)
        ]
    ] | None = None # TODO: optional or not?

    @model_validator(mode="before")
    def validate_keywords(cls, data: dict) -> dict:
        """
        Validate and filter out misconfigured entries before validation.
        Also validates regex patterns.
        """
        if isinstance(data, dict) and "keywords" in data and isinstance(data["keywords"], list):
            data["keywords"] = validate_keywords(data["keywords"])
        return data