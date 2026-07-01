import re
from enum import Enum


class MonitorType(Enum):
    """Types of monitoring targets supported by LoggiFly."""
    CONTAINER = "container"
    SWARM = "swarm"

# NTFY_PREFIX = "ntfy_"
# APPRISE_PREFIX = "apprise_"
# WEBHOOK_PREFIX = "webhook_"

class NotificationPrefix(Enum):
    NTFY = "ntfy_"
    APPRISE = "apprise_"
    WEBHOOK = "webhook_"

# Log Pattern Constants
# These patterns are used to detect the start of new log entries in multi-line mode.
# When a pattern is detected, it indicates the beginning of a new log entry,
# allowing proper grouping of multi-line log entries.

# Strict patterns are more reliable and have higher priority during pattern detection
STRICT_PATTERNS = [
    # Timestamp and log level at line start
    r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})?\] \[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]", 
    r"^\d{4}-\d{2}-\d{2}(?:, | )\d{2}:\d{2}:\d{2}(?:,\d{3})? (?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)",

    # ISO timestamp in brackets
    r"^\[\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\]", # [2025-02-17T03:23:07Z] or [2025-02-17 04:22:59 +0100] or [2025-02-18T03:23:05.436627]

    # Month in brackets
    r"^\[(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\]",
    r"^\[\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\]", # [17/Feb/2025:10:13:02 +0000]

    # ISO timestamp without brackets
    r"^\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b",

    # Month without brackets
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\b",
    r"\b\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\b",   # 17/Feb/2025:10:13:02 +0000
    
    # Unix-like timestamps
    r"^\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{2,6}\]",
    
    # Log level at line start
    r"^\[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",
    r"^\((?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\)"
]

# Flex patterns are used as a fallback if strict patterns don't match enough lines
FLEX_PATTERNS = [
    # Generic timestamps (fallback)
    r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
    r"\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b", # 2025-02-17T03:23:07Z
    r"\b(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])-\d{4} \d{2}:\d{2}:\d{2}\b",
    r"(?i)\b\d{2}\/\d{2}\/\d{4}(?:,\s+|:|\s+])\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?\b",
    r"\b\d{10}\.\d+\b",                                                          # 1739762586.0394847
    # Log level (fallback)
    r"(?i)(?<=^)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",      
    r"(?i)(?<=\s)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",
    r"(?i)\[(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\]",
    r"(?i)\((?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\)",
    r"(?i)\d{2}/\d{2}/\d{4},\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
]

# Pre-compile patterns for better performance during log processing
COMPILED_STRICT_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in STRICT_PATTERNS]
COMPILED_FLEX_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in FLEX_PATTERNS]

# Emoji detection regex
EMOJI_PATTERN = re.compile(
    "[\U0001F300-\U0001FAFF"  # symbols & pictographs
    "\U00002700-\U000027BF"   # dingbats
    "\U0001F1E0-\U0001F1FF"   # flags
    "\U0001F900-\U0001F9FF"   # supplemental symbols
    "\U00002600-\U000026FF"   # misc symbols
    "]+",
    flags=re.UNICODE
)

class Actions(Enum):
    """Available container actions that can be triggered by keywords."""
    STOP = "stop"
    RESTART = "restart"
    START = "start"

class NotificationType(Enum):
    """Types of notifications that can be triggered by keywords."""
    LOG_MATCH = "log_match"
    DOCKER_EVENT = "event"

MAP_CONFIG_EVENTS_TO_DOCKER_EVENTS = {
    "start": "start",
    "stop": "stop",
    "die": "die",
    "crash": "die", # with exitCode != 0
    "destroy": "destroy",
    "healthy": "health_status: healthy",
    "unhealthy": "health_status: unhealthy",
    "starting": "health_status: starting",
    "oom": "oom",
    "kill": "kill",
    "create": "create",
    "restart": "restart"
}

SUPPORTED_CONTAINER_ACTIONS: tuple[str, ...] = tuple(action.value for action in Actions)
SUPPORTED_CONTAINER_EVENTS = tuple(MAP_CONFIG_EVENTS_TO_DOCKER_EVENTS.keys())

BUFFERED_SUFFIX = (
    "{% if buffer_elapsed_seconds|default(0, true)|int > 0 %}"
    " {{ buffer_match_count|default(1) }} "
    "{% if buffer_match_count|default(1)|int == 1 %}time{% else %}times{% endif %}"
    " within {{ buffer_elapsed_seconds }}s"
    "{% endif %}"
)

DEFAULT_LOG_MATCH_TITLE = (
    "{% set count = keywords_list|default([], true)|length %}"
    "{% if count == 1 %}"
    "'{{ keywords_list[0] }}' was found" + BUFFERED_SUFFIX + " in {{ target_name }}"
    "{% elif count == 2 %}"
    "'{{ keywords_list[0] }}' and '{{ keywords_list[1] }}' were found in {{ target_name }}"
    "{% elif count > 2 %}"
    "The following keywords were found in {{ target_name }}: "
    "{% for keyword in keywords_list %}"
    "'{{ keyword }}'{% if not loop.last %}, {% endif %}"
    "{% endfor %}"
    "{% else %}"
    "{{ target_name }}"
    "{% endif %}"
)

DEFAULT_TITLE_WRAPPER = (
    "{% if host_identifier %}[{{ host_identifier }}] - {% endif %}"
    "{{ title }}"
    "{% if container_action_result_message is not none %}"
    " ({{ container_action_result_message }})"
    "{% endif %}"
)


MAP_EVENT_TO_TITLE = {
    "start":     "Container '{{ target_name }}' started" + BUFFERED_SUFFIX,
    "stop":      "Container '{{ target_name }}' stopped" + BUFFERED_SUFFIX,
    "die":       "Container '{{ target_name }}' exited" + BUFFERED_SUFFIX,
    "crash":     "Container '{{ target_name }}' crashed" + BUFFERED_SUFFIX,
    "destroy":   "Container '{{ target_name }}' removed" + BUFFERED_SUFFIX,
    "healthy":   "Container '{{ target_name }}' entered healthy state" + BUFFERED_SUFFIX,
    "unhealthy": "Container '{{ target_name }}' entered unhealthy state" + BUFFERED_SUFFIX,
    "starting":  "Container '{{ target_name }}' entered starting state" + BUFFERED_SUFFIX,
    "oom":       "OOM event for container '{{ target_name }}'" + BUFFERED_SUFFIX,
    "kill":      "Container '{{ target_name }}' was killed" + BUFFERED_SUFFIX,
    "create":    "Container '{{ target_name }}' was created" + BUFFERED_SUFFIX,
    "restart":   "Container '{{ target_name }}' was restarted" + BUFFERED_SUFFIX,
}

MAP_EVENT_TO_MESSAGE = {
    "start":     "Container '{{ target_name }}' was started.",
    "stop":      "Container '{{ target_name }}' was stopped by a stop request.",
    "die":       "Container '{{ target_name }}' exited. Exit code: {{ exit_code }}.",
    "crash":     "Container '{{ target_name }}' exited unexpectedly. Exit code: {{ exit_code }}.",
    "destroy":   "Container '{{ target_name }}' was removed.",
    "healthy":   "Health status for container '{{ target_name }}' changed to healthy.",
    "unhealthy": "Health status for container '{{ target_name }}' changed to unhealthy.",
    "starting":  "Health status for container '{{ target_name }}' changed to starting.",
    "oom":       "Container '{{ target_name }}' ran out of memory (OOM).",
    "kill":      "Container '{{ target_name }}' was killed (signal: {{ signal }}).",
    "create":    "Container '{{ target_name }}' was created.",
    "restart":   "Container '{{ target_name }}' was restarted.",
}
