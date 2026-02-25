import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, List, Any

from jinja2 import Environment, Undefined

from constants import NotificationType, MAP_EVENT_TO_MESSAGE, MAP_EVENT_TO_TITLE, MonitorType
from monitoring.base import SourceMetadata

logger = logging.getLogger(__name__)


class _WarnUndefined(Undefined):
    def __str__(self):
        logger.warning(f"Template variable '{{{{ {self._undefined_name} }}}}' is not defined")
        return ""


_jinja_env = Environment(undefined=_WarnUndefined)


def _render_template(template: str, data: Dict[str, Any]) -> str:
    try:
        tmpl = _jinja_env.from_string(template)
        return tmpl.render(**data)
    except Exception as e:
        logger.warning(f"Template rendering failed: {e}")
        return template


def extract_fields_from_json(log_line: str) -> Dict[str, Any]:
    """Parse a log line as JSON; return fields or empty dict on failure."""
    if not log_line:
        return {}
    try:
        return json.loads(log_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    except Exception as e:
        logger.error(f"Unexpected error parsing log line as JSON: {e}")
        return {}


def extract_fields_from_regex(log_line: str, regex: Optional[str]) -> Dict[str, Any]:
    """Extract named capture groups from regex applied to the log line."""
    if not (log_line and regex):
        return {}
    try:
        match = re.search(regex, log_line, re.IGNORECASE)
        return match.groupdict() if match else {}
    except re.error as e:
        logger.warning(f"Invalid regex '{regex}': {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error extracting fields from regex: {e}")
        return {}

def default_title_for_log_match(
    keywords_found: List[str],
    target_name: str,
) -> str:
    """Preserve current default title semantics for log matches."""
    if len(keywords_found) == 1:
        title = f"'{keywords_found[0]}' found in {target_name}"
    elif len(keywords_found) == 2:
        joined = " and ".join(f"'{w}'" for w in keywords_found)
        title = f"{joined} found in {target_name}"
    elif len(keywords_found) > 2:
        joined = ", ".join(f"'{w}'" for w in keywords_found)
        title = f"The following keywords were found in {target_name}: {joined}"
    else:
        title = target_name
    return title


def fallback_title_for_event(target_name: str, event: Optional[str]) -> str:
    return f"Event '{event}' for container {target_name}" if event else f"Event for container {target_name}"


@dataclass
class NotificationContext:
    """
    Normalised data used by title/message renderers.
    Only add fields here that make sense for both logs and events.
    """

    notification_type: NotificationType
    target_name: str
    monitor_type: MonitorType
    hostname: Optional[str] = None
    host_identifier: Optional[str] = None # hostname for multi-host setups, "manager@node1" or "worker@node2" for swarm, else None
  
    # log match fields
    log_line: Optional[str] = None
    regex: Optional[str] = None
    keywords_found: List[str] = field(default_factory=list)
    trigger_on: Optional[dict] = None
    trigger_on_count: Optional[int] = None
    trigger_on_timeframe: Optional[int] = None
  
    # container event fields
    event: Optional[str] = None
    exit_code: Optional[int] = None
    signal: Optional[str] = None

    # action fields
    action_type: Optional[str] = None
    action_string: Optional[str] = None
    action_target: Optional[str] = None
    action_result: Optional[str] = None
    action_succeeded: Optional[bool] = None

    extra_fields: Dict[str, Any] = field(default_factory=dict)
    time: Optional[int | float] = None

    # from source metadata
    source_metadata: Optional[SourceMetadata] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    swarm_service_name: Optional[str] = None
    stack_name: Optional[str] = None
    image: Optional[str] = None

    def __post_init__(self):
        # Extract fields from source metadata
        if self.source_metadata:
            self.image = self.source_metadata.image if not self.image else self.image
            self.container_id = self.source_metadata.container_id if not self.container_id else self.container_id
            self.swarm_service_name = self.source_metadata.service_name if not self.swarm_service_name else self.swarm_service_name
            self.stack_name = self.source_metadata.stack_name if not self.stack_name else self.stack_name
            self.container_name = self.source_metadata.container_name if not self.container_name else self.container_name
        
        if self.trigger_on:
            self.trigger_on_count = self.trigger_on.get("count")
            self.trigger_on_timeframe = self.trigger_on.get("timeframe")

    def get_defaults(self) -> Dict[str, Any]:
        # Convert Unix timestamp to datetime or use current time
        if self.time is not None:
            try:
                dt = datetime.fromtimestamp(self.time)
            except (ValueError, OSError, OverflowError) as e:
                logging.warning(f"Invalid timestamp {self.time}: {e}, using current time")
                dt = datetime.now()
        else:
            dt = datetime.now()

        # These are the default template fields that are always available
        defaults = {
            "notification_type": self.notification_type.value,

            "container_id": self.container_id[:12] if self.container_id else None,
            "full_container_id": self.container_id,
            "container_name": self.container_name,
            "service_name": self.swarm_service_name,
            "stack_name": self.stack_name,
            "target_name": self.target_name,
            "container": self.target_name, # legacy template field
            "docker_image": self.image,
            
            "hostname": self.hostname,
            "host_identifier": self.host_identifier,
            "monitor_type": self.monitor_type.value,

            "original_log_line": self.log_line,
            "log_entry": self.log_line,
            "keywords": ", ".join(f"'{w}'" for w in self.keywords_found) if self.keywords_found else None,
            "keyword": ", ".join(f"'{w}'" for w in self.keywords_found) if self.keywords_found else None,
            "keywords_list": self.keywords_found,
            "trigger_on_count": self.trigger_on_count,
            "trigger_on_timeframe": self.trigger_on_timeframe,

            
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "date": dt.strftime("%Y-%m-%d"),
            "time": dt.strftime("%H:%M:%S"),
            "datetime": dt.strftime("%Y-%m-%d %H:%M:%S"),

            "event": self.event,
            "exit_code": self.exit_code,
            "signal": self.signal,

            "action_type": self.action_type,
            "action_string": self.action_string,
            "action_target": self.action_target,
            "action_result_message": self.action_result,
            "action_succeeded": self.action_succeeded,
        }

        return defaults

    def get_regex_fields(self) -> Dict[str, Any]:
        return extract_fields_from_regex(self.log_line, self.regex) if self.log_line and self.regex else {}
    
    def get_json_fields(self) -> Dict[str, Any]:
        return extract_fields_from_json(self.log_line) if self.log_line else {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Build the base dict used for templating. Order of precedence:
        1) explicit extra_fields
        2) extracted fields from json if log entry is json
        3) extracted fields from regex named groups
        4) canonical defaults (container, keywords, keyword, event, hostname, monitor_type)
        """
        defaults = self.get_defaults()
        regex_fields = self.get_regex_fields()
        json_fields = self.get_json_fields()

        ctx: Dict[str, Any] = {}
        ctx.update(defaults)
        ctx.update(regex_fields)
        ctx.update(json_fields)
        ctx.update(self.extra_fields or {})
        return ctx


def render_title(
    ctx: NotificationContext,
    template: Optional[str] = None,
) -> str:
    """
    Render a notification title.
    """
    context_dict = ctx.to_dict()
    title = None
    if template:
        title = _render_template(template, context_dict)

    # Default when no template is provided
    if not title:
        if ctx.notification_type == NotificationType.LOG_MATCH:
            title = default_title_for_log_match(ctx.keywords_found, ctx.target_name)
        elif ctx.notification_type == NotificationType.DOCKER_EVENT:
            if ctx.event:
                logger.debug(f"Rendering title for event: {ctx.event} with template: {MAP_EVENT_TO_TITLE.get(ctx.event, '')}")
                title = _render_template(MAP_EVENT_TO_TITLE.get(ctx.event, ""), context_dict)
                if not title:
                    title = fallback_title_for_event(ctx.target_name, ctx.event)

        # Prepend host identifier to title (only exists for multi-host or swarm setups)
        if ctx.host_identifier:
            title = f"[{ctx.host_identifier}] - {title}"
        if ctx.action_result is not None:
            title = f"{title} ({ctx.action_result})"

    # Safe fallback
    if not title:
        title = f"{ctx.target_name}: {context_dict.get('keywords') or context_dict.get('event')}"
    # Append action result to title
    return title


def render_message(
    ctx: NotificationContext,
    template: Optional[str] = None,
    default_message: Optional[str] = None,
) -> str:
    """
    Render a notification message.
    - template: preferred message_template (can use any fields from ctx.to_dict()).
    Falls back to default_message or original log line.
    """
    context_dict = ctx.to_dict()

    if template:
        logger.debug(f"Rendering message with template: {template}")
        return _render_template(template, context_dict)
    # Fallback default message for events
    if ctx.notification_type == NotificationType.DOCKER_EVENT:
        if ctx.event in MAP_EVENT_TO_MESSAGE:
            rendered = _render_template(MAP_EVENT_TO_MESSAGE[ctx.event], context_dict)
            if rendered:
                return rendered
    # Fallback
    return default_message or ctx.log_line or ""
