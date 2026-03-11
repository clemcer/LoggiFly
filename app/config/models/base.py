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
        populate_by_name=True,
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

class SystemNotifications(BaseConfigModel):
    start: bool = Field(True, description="Enable the notification sent when LoggiFly starts.")
    shutdown: bool = Field(True, description="Enable the notification sent when LoggiFly shuts down.")
    config_reload: bool = Field(True, description="Enable the notification sent when the config file is reloaded.")
    monitor_event: bool = Field(True, description="Enable the notification sent when a container starts or stops being monitored.")


class SettingsConfig(BaseConfigModel):
    """Application-wide settings that control LoggiFly's behaviour."""
    log_level: str = Field("INFO", description="Log verbosity level. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`.")
    multi_line_entries: bool = Field(True, description="Catch log entries that span multiple lines instead of going line by line.")
    compact_summary_message: bool = Field(False, description="Get a comma-separated list of monitored targets instead of a multi-line list in startup and config reload notifications.")
    reload_config: bool = Field(True, description="Automatically reload configuration when the config file changes.")
    system_notifications: SystemNotifications | bool = Field(SystemNotifications(), description="System notifications settings. Can be set to a boolean to enable or disable all notifications or to a SystemNotifications object to enable or disable specific notifications.") # type: ignore[call-arg]
    log_target_configs: bool = Field(False, description="Log the effective configuration for each target to the console.")

    def is_notification_enabled(self, type_string: str) -> bool:
        if isinstance(self.system_notifications, bool):
            return self.system_notifications
        if isinstance(self.system_notifications, SystemNotifications):
            return getattr(self.system_notifications, type_string)
        return False


# ================================================
# Misc Config Models (shared between models)
# ================================================
class SimpleKeyword(BaseConfigModel):
    """A plain-text keyword for use in ignore or all_of lists."""
    keyword: str = Field(description="Plain text string to search for in log lines.")

class SimpleRegex(BaseConfigModel):
    """A regex pattern for use in ignore or all_of lists."""
    regex: str = Field(description="Regular expression to match against log lines.")

SimpleKeywords = List[
    Annotated[
        Union[
            Annotated[SimpleKeyword, Tag("keyword")],
            Annotated[SimpleRegex, Tag("regex")],
        ],
    Discriminator(discriminate_keyword_type)]]

class NtfyViewAction(BaseConfigModel):
    """Ntfy action that opens a URL when tapped."""
    action: Literal["view"] = Field("view", description="Action type. Must be `view`.")
    label: str = Field(description="Button label shown in the notification.")
    url: str = Field(description="URL to open when the action button is tapped.")
    clear: Optional[bool] = Field(False, description="Clear the notification after the action is triggered.")

class NtfyBroadcastAction(BaseConfigModel):
    """Ntfy action that sends an Android broadcast intent."""
    action: Literal["broadcast"] = Field("broadcast", description="Action type. Must be `broadcast`.")
    label: str = Field(description="Button label shown in the notification.")
    clear: Optional[bool] = Field(False, description="Clear the notification after the action is triggered.")
    intent: Optional[str] = Field(None, description="Android intent for the broadcast action.")
    extras: Optional[dict] = Field(None, description="Extra key-value pairs for the Android intent.")

class NtfyHttpAction(BaseConfigModel):
    """Ntfy action that performs an HTTP request."""
    action: Literal["http"] = Field("http", description="Action type. Must be `http`.")
    label: str = Field(description="Button label shown in the notification.")
    url: str = Field(description="URL called by the HTTP action.")
    clear: Optional[bool] = Field(False, description="Clear the notification after the action is triggered.")
    method: Optional[str] = Field(None, description="HTTP method for the request (e.g. `GET`, `POST`).")
    headers: Optional[dict] = Field(None, description="Custom HTTP headers to include in the request.")
    body: Optional[str] = Field(None, description="Request body for the HTTP action.")

NtfyAction = Annotated[
    Union[NtfyViewAction, NtfyHttpAction, NtfyBroadcastAction],
    Field(discriminator="action")
]

# ================================================
# Defaults Config Model
# ================================================

class NotificationDefaults(BaseConfigModel):
    """Notification service credentials and settings that can be set at the defaults level."""
    ntfy_tags: Optional[str] = Field(None, description="Comma-separated Ntfy tags or emoji shortcodes to include in the notification header.")
    ntfy_topic: Optional[str] = Field(None, description="Ntfy topic to publish notifications to.")
    ntfy_priority: Optional[Union[str, int]] = Field(None, description="Notification priority. One of `min`, `low`, `default`, `high`, `max` (or 1–5).")
    ntfy_url: Optional[str] = Field(None, description="Base URL of the Ntfy server (e.g. `https://ntfy.sh`).")
    ntfy_token: Optional[SecretStr] = Field(None, description="Authentication token for Ntfy.")
    ntfy_username: Optional[str] = Field(None, description="Username for Ntfy basic authentication.")
    ntfy_password: Optional[SecretStr] = Field(None, description="Password for Ntfy basic authentication.")
    ntfy_icon: Optional[str] = Field(None, description="URL of an icon to display with the notification.")
    ntfy_click: Optional[str] = Field(None, description="URL to open when the notification is clicked.")
    ntfy_markdown: Optional[bool] = Field(None, description="Render the notification body as Markdown.")
    ntfy_actions: Optional[List[NtfyAction]] = Field(None, description="List of Ntfy action buttons to attach to the notification.")
    ntfy_headers: Optional[dict] = Field(None, description="Custom HTTP headers to include in the Ntfy request.")

    apprise_url: Optional[SecretStr] = Field(None, description="Apprise-compatible notification URL (supports 100+ services).")

    webhook_url: Optional[str] = Field(None, description="HTTP endpoint to POST notification payloads to.")
    webhook_headers: Optional[dict] = Field(None, description="Custom HTTP headers for webhook requests.")

    @field_validator("ntfy_actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_ntfy_priority(v)

class EmptyDefaults(NotificationDefaults):
    """Shared optional settings for notifications and template customization."""
    ignore_keywords: Optional[SimpleKeywords] = Field(None, description="Keywords or regexes to suppress — matching log lines will not trigger notifications.")
    title_template: Optional[str] = Field(None, description="Jinja2 template for the notification title. Use `{{ variable }}` placeholders (e.g. `{{ container_name }}`, `{{ keyword }}`).")
    message_template: Optional[str] = Field(None, description="Jinja2 template for the notification message body. Use `{{ variable }}` placeholders (e.g. `{{ log_entry }}`, `{{ keyword }}`).")
    olivetin_url: Optional[str] = Field(None, description="Base URL of the OliveTin instance to trigger actions on.")
    olivetin_username: Optional[str] = Field(None, description="Username for OliveTin authentication.")
    olivetin_password: Optional[SecretStr] = Field(None, description="Password for OliveTin authentication.")

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
    """Optional overridable settings that can be applied at the container, rule, or keyword level."""

    attach_logfile: Optional[bool] = Field(None, description="Attach recent log lines as a file to the notification.")
    trigger_cooldown: Optional[int] = Field(None, description="Minimum seconds between repeated triggers for the same keyword on the same target. `0` disables cooldown.")
    container_action_cooldown: Optional[int] = Field(None, description="Minimum seconds between repeated container actions (restart/stop) on the same target.")
    attachment_lines: Optional[int] = Field(None, description="Number of log lines to include in the log attachment.")
    hide_full_regex: Optional[bool] = Field(None, description="In notifications, hide the full regex match and only show named capturing groups.")
    regex_case_sensitive: Optional[bool] = Field(None, description="Whether regex patterns are case-sensitive.")
    disable_trigger_notifications: Optional[bool] = Field(None, description="Suppress all trigger notifications. Useful when only container actions or OliveTin actions are needed.")
    merge_matches: Optional[bool] = Field(None, description="Combine multiple keyword matches from the same log entry into a single notification.")

class RootDefaultsConfig(EmptyDefaults, ActionCooldownMixin):
    """Global default settings applied to all rules unless overridden at a lower level."""
    attach_logfile: bool = Field(False, description="Attach recent log lines as a file to the notification.")
    trigger_cooldown: int = Field(0, description="Minimum seconds between repeated triggers for the same keyword on the same target. `0` disables cooldown.")
    container_action_cooldown: int = Field(60, description="Minimum seconds between repeated container actions (restart/stop) on the same target.")
    attachment_lines: int = Field(20, description="Number of log lines to include in the log attachment.")
    hide_full_regex: bool = Field(False, description="In notifications, hide the full regex match and only show named capturing groups.")
    regex_case_sensitive: bool = Field(True, description="Whether regex patterns are case-sensitive.")
    disable_trigger_notifications: bool = Field(False, description="Suppress all trigger notifications. Useful when only container actions or OliveTin actions are needed.")
    merge_matches: bool = Field(False, description="Combine multiple keyword matches from the same log entry into a single notification.")


# ================================================
# Notifications Config Models
# ================================================

class NtfyConfig(BaseConfigModel):
    """Configuration for the Ntfy push notification service."""
    url: str = Field(description="Base URL of the Ntfy server (e.g. `https://ntfy.sh`).")
    topic: str = Field(description="Ntfy topic to publish notifications to.")
    token: Optional[SecretStr] = Field(None, description="Authentication token for Ntfy.")
    username: Optional[str] = Field(None, description="Username for Ntfy basic authentication.")
    password: Optional[SecretStr] = Field(None, description="Password for Ntfy basic authentication.")
    priority: Optional[Union[str, int]] = Field(3, description="Notification priority. One of `min`, `low`, `default`, `high`, `max` (or 1–5).")
    tags: Optional[str] = Field("kite,mag", description="Comma-separated Ntfy tags or emoji shortcodes to include in the notification header.")
    icon: Optional[str] = Field(None, description="URL of an icon to display with the notification.")
    click: Optional[str] = Field(None, description="URL to open when the notification is clicked.")
    markdown: Optional[bool] = Field(None, description="Render the notification body as Markdown.")
    actions: Optional[List[NtfyAction]] = Field(None, description="List of Ntfy action buttons to attach to the notification.")
    headers: Optional[dict] = Field(None, description="Custom HTTP headers to include in the Ntfy request.")

    @field_validator("priority", mode="before")
    def validate_ntfy_priority(cls, v):
        return validate_ntfy_priority(v)

    @field_validator("actions", mode="before")
    def validate_ntfy_actions(cls, v):
        if v and isinstance(v, list):
            return validate_ntfy_actions(v)
        return v

class AppriseConfig(BaseConfigModel):
    """Configuration for the Apprise multi-service notification library."""
    url: SecretStr = Field(description="Apprise-compatible notification URL (supports 100+ services).")

class WebhookConfig(BaseConfigModel):
    """Configuration for webhook-based notifications."""
    url: str = Field(description="HTTP endpoint to POST notification payloads to.")
    headers: Optional[dict] = Field(None, description="Custom HTTP headers for webhook requests.")

class NotificationsConfig(BaseConfigModel):
    """Configuration for all notification services."""
    ntfy: Optional[NtfyConfig] = Field(None, description="Ntfy push notification service configuration.")
    apprise: Optional[AppriseConfig] = Field(None, description="Apprise multi-service notification configuration.")
    webhook: Optional[WebhookConfig] = Field(None, description="Webhook notification configuration.")


# ================================================
# Keyword Config Models
# ================================================

class OliveTinArgument(BaseConfigModel):
    """A named argument passed to an OliveTin action."""
    name: str = Field(description="Argument name.")
    value: str = Field(description="Argument value.")

class OliveTinAction(BaseConfigModel):
    """An OliveTin action to trigger when a keyword is matched."""
    id: str = Field(description="ID of the OliveTin action to trigger.")
    arguments: Optional[List[OliveTinArgument]] = Field(None, description="List of named arguments to pass to the OliveTin action.")

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
    container_action: Optional[str] = Field(None, description="Action to perform on the container when this keyword is matched. One of `restart`, `stop`, `start`. Use 'action@container_name' to perform the action on a different container (this is always limited to the same host).")
    olivetin_actions: Optional[List[OliveTinAction]] = Field(None, description="List of OliveTin actions to trigger when this keyword is matched.")

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
    count: int = Field(ge=2, description="Number of matches required within the timeframe to trigger.")
    timeframe: int = Field(ge=1, description="Time window in seconds within which `count` matches must occur.")

class TriggerOnBase(BaseConfigModel):
    trigger_on: Optional[TriggerOnConfig] = Field(None, description="Only trigger after a keyword matches a set number of times within a timeframe.")

    @field_validator("trigger_on", mode="before")
    def validate_trigger_on(cls, v):
        return validate_trigger_on(v)

class TriggerActionsBase(ModularDefaultsConfig, TriggerActions, TriggerOnBase):
    """Base class for keyword items with common fields for actions and templates."""
    pass


class RegexItem(TriggerActionsBase):
    """
    A regex-based keyword with optional per-keyword settings.
    Named capturing groups can be referenced in notification templates.
    """
    regex: str = Field(description="Regular expression to match against log lines. Named capturing groups can be used in notification templates.")


class KeywordItem(TriggerActionsBase):
    """A plain-text keyword with optional per-keyword settings."""
    keyword: str = Field(description="Plain text string to search for in log lines.")


class AllOf(TriggerActionsBase):
    """
    A set of keywords/regexes that must all match within the same log entry to trigger.
    """
    all_of: SimpleKeywords = Field(description="List of keywords/regexes that must all be present in a log entry to trigger.")


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
                Annotated[AllOf, Tag("all_of")]],
            Discriminator(discriminate_keyword_type)
        ]
    ] | None = Field(None, description="List of keywords, regexes, or `all_of` groups to match in log lines.")

    @model_validator(mode="before")
    def validate_keywords(cls, data: dict) -> dict:
        """
        Validate and filter out misconfigured entries before validation.
        Also validates regex patterns.
        """
        if isinstance(data, dict) and "keywords" in data and isinstance(data["keywords"], list):
            data["keywords"] = validate_keywords(data["keywords"])
        return data


class GlobalConfig(KeywordBase):
    """Global configuration for defaults and keywords."""
    defaults: RootDefaultsConfig = Field(RootDefaultsConfig(), description="Global default settings applied to all rules unless overridden.")  # type: ignore[call-arg]
