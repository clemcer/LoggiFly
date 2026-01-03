import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, List, Any

from constants import NotificationType, MAP_EVENT_TO_MESSAGE, MAP_EVENT_TO_TITLE, MonitorType
from docker_monitoring.docker_helpers import ContainerSnapshot

logger = logging.getLogger(__name__)


class SafeDict(dict):
    """
    dict subclass that remembers missing keys so callers can decide
    whether to fall back to a default value.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.missing_keys = set()

    def __missing__(self, key):
        self.missing_keys.add(key)
        return "{" + key + "}"


def _extract_fields_from_json(log_line: str) -> Dict[str, Any]:
    """Parse a log line as JSON; return fields or empty dict on failure."""
    if not log_line:
        return {}
    try:
        return json.loads(log_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    except Exception as exc:
        logging.error(f"Unexpected error parsing log line as JSON: {exc}")
        return {}


def _extract_fields_from_regex(log_line: str, regex: Optional[str]) -> Dict[str, Any]:
    """Extract named capture groups from regex applied to the log line."""
    if not (log_line and regex):
        return {}
    try:
        match = re.search(regex, log_line, re.IGNORECASE)
        return match.groupdict() if match else {}
    except re.error as exc:
        logging.warning(f"Invalid regex '{regex}': {exc}")
        return {}


def get_template_fields(
    log_line: str,
    regex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Collect candidate template fields from a log line.

    - include JSON fields and regex named groups (if regex provided)
    """
    fields: Dict[str, Any] = {}
    fields.update(_extract_fields_from_json(log_line))
    if regex:
        for key, value in _extract_fields_from_regex(log_line, regex).items():
            fields.setdefault(key, value)
    return fields


def _format_with_safe_dict(template: str, data: Dict[str, Any]) -> tuple[str, set]:
    try:
        safe = SafeDict(data)
        rendered = template.format_map(safe)
        return rendered, safe.missing_keys
    except Exception as e:
        logging.error(f"Error formatting template: {e}")
        return template, set()


def default_title_for_log_match(
    keywords_found: List[str],
    unit_name: str,
) -> str:
    """Preserve current default title semantics for log matches."""
    if len(keywords_found) == 1:
        title = f"'{keywords_found[0]}' found in {unit_name}"
    elif len(keywords_found) == 2:
        joined = " and ".join(f"'{w}'" for w in keywords_found)
        title = f"{joined} found in {unit_name}"
    elif len(keywords_found) > 2:
        joined = ", ".join(f"'{w}'" for w in keywords_found)
        title = f"The following keywords were found in {unit_name}: {joined}"
    else:
        title = unit_name
    return title


def default_title_for_event(unit_name: str, event: Optional[str]) -> str:
    return f"Event '{event}' for container {unit_name}" if event else f"Event for container {unit_name}"


@dataclass
class NotificationContext:
    """
    Normalised data used by title/message renderers.
    Only add fields here that make sense for both logs and events.
    """

    notification_type: NotificationType
    unit_name: str
    monitor_type: MonitorType

    hostname: Optional[str] = None
    host_identifier: Optional[str] = None # hostname for multi-host setups, "manager@node1" or "worker@node2" for swarm, else None
    log_line: Optional[str] = None
    regex: Optional[str] = None
    keywords_found: List[str] = field(default_factory=list)
    event: Optional[str] = None
    exit_code: Optional[int] = None
    action_result: Optional[str] = None
    extra_fields: Dict[str, Any] = field(default_factory=dict)
    time: Optional[int | float] = None

    container_snapshot: Optional[ContainerSnapshot] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    swarm_service_name: Optional[str] = None
    stack_name: Optional[str] = None
    
    def __post_init__(self):
        self.container_id = self.container_snapshot.id if self.container_snapshot else None
        self.swarm_service_name = self.container_snapshot.service_name if self.container_snapshot else None
        self.stack_name = self.container_snapshot.stack_name if self.container_snapshot else None
        self.container_name = self.container_snapshot.name if self.container_snapshot else None


    def to_dict(self) -> Dict[str, Any]:
        """
        Build the base dict used for templating. Order of precedence:
        1) explicit extra_fields
        2) extracted fields from log_line / regex
        3) canonical defaults (container, keywords, keyword, event, hostname, monitor_type)
        """
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
            "container_id": self.container_id,
            "container_name": self.container_name,
            "swarm_service_name": self.swarm_service_name,
            "stack_name": self.stack_name,
            "unit_name": self.unit_name,
            "keywords": ", ".join(f"'{w}'" for w in self.keywords_found) if self.keywords_found else "",
            "keyword": ", ".join(f"'{w}'" for w in self.keywords_found) if self.keywords_found else "",
            "event": self.event,
            "hostname": self.hostname,
            "host_identifier": self.host_identifier,
            "monitor_type": self.monitor_type.value,
            "original_log_line": self.log_line,
            "log_entry": self.log_line,
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "date": dt.strftime("%Y-%m-%d"),
            "time": dt.strftime("%H:%M:%S"),
            "datetime": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "exit_code": self.exit_code,
            "action_result": self.action_result,
        }

        extracted = get_template_fields(self.log_line, regex=self.regex) if self.log_line else {}

        ctx: Dict[str, Any] = {}
        ctx.update(defaults)
        ctx.update(extracted)
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
        rendered, missing = _format_with_safe_dict(template, context_dict)
        if missing:
            logging.warning(f"Missing keys in title template: {missing}.")
        title = rendered

    # Default when no template is provided
    if not title:
        if ctx.notification_type == NotificationType.LOG_MATCH:
            title = default_title_for_log_match(ctx.keywords_found, ctx.unit_name)
        elif ctx.notification_type == NotificationType.DOCKER_EVENT:
            if ctx.event:
                logger.debug(f"Rendering title for event: {ctx.event} with template: {MAP_EVENT_TO_TITLE.get(ctx.event, '')} and context: {context_dict}")
                title, missing = _format_with_safe_dict(MAP_EVENT_TO_TITLE.get(ctx.event, ""), context_dict)
                if missing:
                    logging.warning(f"Missing keys in event default title template: {missing}.")
            if not title: # fallback
                title = default_title_for_event(ctx.unit_name, ctx.event)

        # Prepend host identifier to title (only exists for multi-host or swarm setups)
        if ctx.host_identifier:
            title = f"[{ctx.host_identifier}] - {title}"

    # Safe fallback
    if not title:
        title = f"{ctx.unit_name}: {context_dict.get('keywords') or context_dict.get('event')}"
    # Append action result to title
    if ctx.action_result is not None:
        title = f"{title} ({ctx.action_result})"
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
        logger.debug(f"Rendering message with template: {template} and context: {context_dict}")
        rendered, missing = _format_with_safe_dict(template, context_dict)
        if missing:
            logging.warning(f"Missing keys in message template: {missing}.")
        return rendered
    # Fallback default message for events
    if ctx.notification_type == NotificationType.DOCKER_EVENT:
        if ctx.event in MAP_EVENT_TO_MESSAGE:
            rendered, missing = _format_with_safe_dict(MAP_EVENT_TO_MESSAGE[ctx.event], context_dict)
            if not missing:
                return rendered
            logging.warning(f"Missing keys in default event message template: {missing}. Falling back to default message.")
    # Fallback
    return default_message or ctx.log_line or ""
