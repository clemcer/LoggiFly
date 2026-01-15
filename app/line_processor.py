import re
import time
from typing import TYPE_CHECKING, Any
import threading
from threading import Thread, Lock
from config.config_model import GlobalConfig, KeywordItem, RegexItem, KeywordGroup, ContainerConfig, SwarmServiceConfig
from constants import (
    COMPILED_STRICT_PATTERNS, 
    COMPILED_FLEX_PATTERNS,
    NotificationType,
)
from notification_formatter import NotificationContext
from utils import merge_modular_settings, merge_with_precedence
from trigger import process_trigger
if TYPE_CHECKING:
    from docker_monitoring.monitor import MonitoredContainerContext, DockerLogMonitor

class LogProcessor:
    """
    Processes Docker container log lines to:
    - Detect and handle multi-line log entries using start patterns.
    - Search for keywords and regex patterns.
    - Trigger notifications and container actions on matches.

    Pattern detection enables grouping of multi-line log entries 
    because every line that does not match the detected pattern is treated as part of the previous entry and added to the buffer.
    """
    # Use the pre-compiled patterns from constants.py
    COMPILED_STRICT_PATTERNS = COMPILED_STRICT_PATTERNS
    COMPILED_FLEX_PATTERNS = COMPILED_FLEX_PATTERNS

    def __init__(self,
                 logger,
                 config: GlobalConfig,
                 unit_config: ContainerConfig | SwarmServiceConfig,
                 monitor_instance: "DockerLogMonitor",
                 unit_context: "MonitoredContainerContext",
                 ):
        """
        Initialize the log processor for a specific container or service.
        
        Args:
            logger: Logger instance for this processor
            config: Global configuration object
            unit_config: Container/service specific configuration
            monitor_instance: DockerLogMonitor instance from which the processor is called
            unit_context: MonitoredContainerContext instance
        """
        self.logger = logger
        self.unit_context = unit_context
        self.unit_stop_event = unit_context.stop_monitoring_event
        self.unit_name = unit_context.unit_name
        self.monitor_type = unit_context.monitor_type
        self.monitor_instance = monitor_instance
        self.unit_config = unit_config

        # Pattern detection state
        self.patterns = []
        self.patterns_count = {pattern: 0 for pattern in self.__class__.COMPILED_STRICT_PATTERNS + self.__class__.COMPILED_FLEX_PATTERNS}
        self.lock_buffer = Lock()
        self.flush_thread_stopped = threading.Event()
        self.flush_thread_stopped.set()
        
        self.waiting_for_pattern = False
        self.valid_pattern = False
        self.line_count = 0
        self.line_limit = 300

        # These are updated in load_config_variables()
        self.multi_line_mode = False 
        self.time_per_keyword = {}
        self.kw_time_lock = Lock()

        self.load_config_variables(config, unit_config)
        
        # If multi-line mode is on, find starting pattern in logs
        if self.multi_line_mode is True:
            self.log_stream_last_updated = time.time()
            self.new_line_event = threading.Event()
            self.buffer = []
            if self.valid_pattern is False:
                log_tail = self._tail_logs(lines=100)
                if log_tail:
                    self._find_starting_pattern(log_tail)
                if self.valid_pattern:
                    self.logger.debug(f"{self.unit_name}: Mode: Multi-Line. Found starting pattern(s) in logs.")
                else:
                    self.logger.debug(f"{self.unit_name}: Mode: Single-Line. Could not find starting pattern in the logs. Continuing the search in the next {self.line_limit - self.line_count} lines")

    def _get_keywords(self, keywords):
        """
        Normalize and return a list of keyword/regex dicts from various input types. 
        """
        returned_keywords = []
        for item in keywords:
            if isinstance(item, str):
                returned_keywords.append(({"keyword": item}))
                continue
            if isinstance(item, (KeywordItem, RegexItem, KeywordGroup)):
                item = item.model_dump(exclude_none=True)
            if isinstance(item, dict) and "keyword_group" in item:
                item["keyword_group"] = tuple(item["keyword_group"])
                returned_keywords.append(item)
            elif isinstance(item, dict) and ("keyword" in item or "regex" in item):
                returned_keywords.append(item)
            else:
                self.logger.debug(f"Did not find correct item type for item: {item}")
        return returned_keywords

    def load_config_variables(self, config: GlobalConfig, unit_config):
        """
        Load and merge configuration for global and container-specific keywords and settings.
        Called on initialization and when reloading config.
        
        Args:
            config: Global configuration object
            unit_config: ContainerConfig or SwarmServiceConfig
        """
        self.config = config
        self.unit_config = unit_config
        self.time_per_keyword = {}
        unt_cnf = self.unit_config.model_dump(exclude_none=True) if self.unit_config else {}
        
        # Merge global and unit-specific keywords
        self.keywords = self._get_keywords(unt_cnf.get("keywords", []))
        self.keywords.extend(self._get_keywords(self.config.global_keywords.keywords))        

        # Merge message configuration with precedence: unit_config > global_config
        self.unit_modular_settings = merge_modular_settings(unt_cnf, config.settings.model_dump(exclude_none=True))
        self.multi_line_mode = config.settings.multi_line_entries
        self.start_flush_thread_if_needed()

    def _find_starting_pattern(self, log):
        """
        Analyze log lines to identify patterns that mark the beginning of new log entries.
        If a pattern is detected frequently enough, it is added to self.patterns and self.valid_pattern is set to True, enabling multi-line log entry grouping.
        If no pattern is found after scanning, self.valid_pattern remains False and the processor falls back to single-line mode (treating each line as a separate entry).
        
        Args:
            log: String containing one or multiple log lines to analyze
        """
        self.waiting_for_pattern = True
        for line in log.splitlines():
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)  # Remove ANSI color codes
            self.line_count += 1
            # Try strict patterns first (higher priority)
            for pattern in self.__class__.COMPILED_STRICT_PATTERNS:
                if pattern.search(clean_line):
                    self.patterns_count[pattern] += 1
                    break
            else:
                # Fall back to flex patterns if no strict pattern matches
                for pattern in self.__class__.COMPILED_FLEX_PATTERNS:
                    if pattern.search(clean_line):
                        self.patterns_count[pattern] += 1
                        break

        # Determine which patterns are frequent enough to be considered valid
        sorted_patterns = sorted(self.patterns_count.items(), key=lambda x: x[1], reverse=True)
        threshold = max(5, int(self.line_count * 0.075))  # At least 7.5% of lines or minimum 5 matches
        
        for pattern, count in sorted_patterns:
            if pattern not in self.patterns and count > threshold:
                self.patterns.append(pattern)
                self.logger.debug(f"{self.unit_name}: Found pattern: {pattern} with {count} matches of {self.line_count} lines. {round(count / self.line_count * 100, 2)}%")
                self.valid_pattern = True
                self.start_flush_thread_if_needed()
        if self.line_count >= self.line_limit and not self.patterns:
            self.logger.info(f"{self.unit_name}: No pattern found in logs after {self.line_limit} lines. Mode: single-line")

        self.waiting_for_pattern = False

    def process_line(self, line: str):
        """        
        Entry point for processing a single log line. 
        If multi-line mode is off or no pattern is detected, processes as single line; 
        otherwise, processes as part of a multi-line entry.
        """
        clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)  # Remove ANSI color codes
        if self.multi_line_mode is False:
            self._search_and_send(clean_line)
        else:
            if self.line_count < self.line_limit:
                self._find_starting_pattern(clean_line)
            if self.valid_pattern is True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_send(clean_line)

    def start_flush_thread_if_needed(self):
        """Start the buffer flush thread if multi-line mode is enabled and a valid pattern is detected."""
        def check_flush():
            """
            Background thread: flushes buffer after one second passed since last log line.
            """
            self.logger.debug(f"Flush Thread started for {self.unit_name}.")
            self.flush_thread_stopped.clear()
            while not self.unit_stop_event.is_set():
                # Wait for new line event to be set but check every 60 seconds if the unit is stopped
                self.new_line_event.wait(60)
                if not self.new_line_event.is_set():
                    continue
                # Check if buffer needs to be flushed after one second passed since last log line
                while True:
                    time.sleep(1)
                    with self.lock_buffer:
                        if (time.time() - self.log_stream_last_updated > 1) or self.unit_stop_event.is_set():
                            if self.buffer:
                                self._handle_and_clear_buffer()
                                self.new_line_event.clear()
                            break
            self.flush_thread_stopped.set()
            self.logger.debug(f"Flush Thread stopped for {self.unit_name}")

        if not self.unit_stop_event.is_set() and self.multi_line_mode and self.valid_pattern and self.flush_thread_stopped.is_set():
            self.flush_thread = Thread(target=check_flush, daemon=True)
            self.flush_thread.start()

    def _handle_and_clear_buffer(self):
        """Flush buffer and process its contents as a single log entry."""
        log_entry = "\n".join(self.buffer)
        self.buffer.clear()
        if log_entry.strip():
            self._search_and_send(log_entry)
        else:
            self.logger.debug(f"Buffer for {self.unit_name} was empty, nothing to process.")

    def _process_multi_line(self, line: str):
        """
        In multi-line mode, determine if the line starts a new entry (pattern match).
        If so, flush buffer; otherwise, append line to buffer.
        """
        # Wait if pattern detection is in progress
        while self.waiting_for_pattern is True:
            time.sleep(1)
        # Check if the line matches any start pattern
        self.log_stream_last_updated = time.time()
        with self.lock_buffer:
            for pattern in self.patterns:
                # If line matches a start pattern, flush buffer and start new entry
                if pattern.search(line):
                    if self.buffer:
                        self._handle_and_clear_buffer()
                    self.buffer.append(line)
                    break
            # Otherwise, append to current buffer (continuation of previous entry)
            else:
                if self.buffer:
                    self.buffer.append(line)
                else:
                    # Fallback: unexpected format, start new buffer
                    self.buffer.append(line)
        self.log_stream_last_updated = time.time()
        self.new_line_event.set()

    def _cooldown_is_expired(self, key: str | tuple[str, ...], notification_cooldown: int, ignore_keyword_time: bool = False) -> bool:
        """check if the keyword is on cooldown"""
        if ignore_keyword_time:
            return True
        with self.kw_time_lock:
            if time.time() - self.time_per_keyword.get(key, 0) >= int(notification_cooldown):
                return True
            else:
                return False

    def _set_keyword_time(self, key: str | tuple[str, ...]):
        """set the keyword time"""
        with self.kw_time_lock:
            self.time_per_keyword[key] = time.time()


    def _search_keyword(self, log_line: str, keyword_dict: dict, ignore_keyword_time: bool = False) -> str | tuple | None:
        """
        Search for keyword or regex in log_line. Enforce notification cooldown unless ignore_keyword_time is True.
        Returns:
            str or None: The matched keyword/regex or None if no match or on cooldown
        """
        def get_keyword_setting(key: str, default: Any = None) -> Any:
            if keyword_dict.get(key) is not None:
                return keyword_dict[key]
            elif self.unit_modular_settings.get(key) is not None:
                return self.unit_modular_settings[key]
            return default

        notification_cooldown = get_keyword_setting("notification_cooldown", 10)
        regex_case_sensitive = get_keyword_setting("regex_case_sensitive", True)

        if regex := keyword_dict.get("regex"):
            if self._cooldown_is_expired(regex, notification_cooldown, ignore_keyword_time):
                match = re.search(regex, log_line, re.IGNORECASE if not regex_case_sensitive else 0)
                if match:
                    self._set_keyword_time(regex)
                    hide_pattern = get_keyword_setting("hide_regex_in_title", False)
                    return "Regex-Pattern" if hide_pattern else f"Regex: {regex}"
        elif keyword := keyword_dict.get("keyword"):
            if self._cooldown_is_expired(keyword, notification_cooldown, ignore_keyword_time):
                if keyword.lower() in log_line.lower():
                    self._set_keyword_time(keyword)
                    return keyword
        elif keyword_group := keyword_dict.get("keyword_group"):
            if self._cooldown_is_expired(keyword_group, notification_cooldown, ignore_keyword_time):
                if all(keyword.lower() in log_line.lower() for keyword in keyword_group):
                    self._set_keyword_time(keyword_group)
                    return keyword_group
        else:
            self.logger.error(f"No keyword or regex found for {keyword_dict}")
        return None

    def _search_and_send(self, log_line):
        """
        Search for keywords/regex in log_line and collect the keyword settings of all found keywords. 
        If a keyword is found, trigger notification and/or get attachment, container action, OliveTin action, etc.
        """
        keywords_found = []
        keyword_level_config = {}
        
        # Search for configured keywords and collect their settings
        for keyword_dict in self.keywords:
            found = self._search_keyword(log_line, keyword_dict)
            if found:
                keyword_level_config = merge_with_precedence(keyword_level_config, keyword_dict, list_union=True)
                keywords_found.append(found)
        if not keywords_found:
            return
            
        # When an excluded keyword is found, the log line gets ignored and the function returns
        if ek := (keyword_level_config.get("excluded_keywords") or []) + (self.unit_modular_settings.get("excluded_keywords") or []):
            for keyword in self._get_keywords(ek):
                found = self._search_keyword(log_line, keyword, ignore_keyword_time=True)
                if found:
                    self.logger.debug(f"Keyword(s) '{keywords_found}' found in '{self.unit_name}' but ignored because excluded keyword '{found}' was found")
                    return

        merged_modular_settings = merge_modular_settings(keyword_level_config, self.unit_modular_settings)
        formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
        self.logger.info(f"The following keywords were found in {self.unit_name}: {keywords_found}."
                    + (f" (A Log FIle will be attached)" if merged_modular_settings.get("attach_logfile") else "")
                    + f"{formatted_log_entry}"
                    )
        self.logger.debug(f"Keyword level config: {keyword_level_config}")
        
        notification_context = NotificationContext(
            notification_type=NotificationType.LOG_MATCH,
            unit_name=self.unit_name,
            monitor_type=self.monitor_type,
            container_snapshot=self.unit_context.snapshot,
            keywords_found=keywords_found,
            log_line=log_line,
            regex=keyword_level_config.get("regex"),
            hostname=self.unit_context.hostname,
            host_identifier=self.unit_context.host_identifier,
        )        
        process_trigger(
            logger=self.logger,
            config=self.config,
            modular_settings=merged_modular_settings,
            trigger_level_config=keyword_level_config,
            monitor_instance=self.monitor_instance,
            unit_context=self.unit_context,
            notification_context=notification_context,
        )

    def _log_attachment(self, number_attachment_lines):
        """Create a log file attachment with the specified number of lines."""
        file_name = f"last_{number_attachment_lines}_lines_from_{self.unit_name}.log"
        try:
            log_tail = self._tail_logs(lines=number_attachment_lines)
            if log_tail:
                return log_tail, file_name
        except Exception as e:
            self.logger.error(f"Could not create log attachment file for Container {self.unit_name}: {e}")
            return None, None

    def _tail_logs(self, lines=100):
        """Tail logs from the container. Calls the tail_logs method of the monitor instance."""
        return self.monitor_instance.tail_logs(self.unit_context.container_id, lines=lines)
