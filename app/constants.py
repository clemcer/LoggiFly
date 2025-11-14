import re
from enum import Enum


class MonitorType(Enum):
    """Types of monitoring targets supported by LoggiFly."""
    CONTAINER = "container"
    SWARM = "swarm"


class MonitorDecision(Enum):
    """Decisions for whether to monitor a container based on labels and configuration."""
    MONITOR = "monitor"
    SKIP = "skip"
    UNKNOWN = "unknown"


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