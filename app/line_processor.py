import re
import time
from typing import Any, cast
import threading
from threading import Thread, Lock

from constants import (
    COMPILED_STRICT_PATTERNS,
    COMPILED_FLEX_PATTERNS,
    NotificationType,
)
from notification_formatter import NotificationContext
from utils import merge_trigger_context, merge_with_precedence, TriggerTracker
from trigger import process_trigger
from config.models import RootConfig
from monitoring import MonitoredTarget, EffectiveTargetConfig


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
                 config: RootConfig,
                 monitored_target: "MonitoredTarget",
                 ):
        """
        Initialize the log processor for a specific container, service, or log file.

        Args:
            logger: Logger instance for this processor
            config: Global configuration object
            target_config: Container/service/logfile specific configuration
            monitored_target: MonitoredTarget instance providing source abstraction
        """
        self.logger = logger
        self.monitored_target = monitored_target
        self.target_stop_event = monitored_target.stop_monitoring_event
        self.target_name = monitored_target.target_name
        self.monitor_type = monitored_target.monitor_type
        self.target_config = monitored_target.target_config

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
        self.keyword_tracker = TriggerTracker(logger=self.logger, trigger_type="keyword")

        self.load_config_variables(config, self.target_config)

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
                    self.logger.debug(f"{self.target_name}: Mode: Multi-Line. Found starting pattern(s) in logs.")
                else:
                    self.logger.debug(f"{self.target_name}: Mode: Single-Line. Could not find starting pattern in the logs. Continuing the search in the next {self.line_limit - self.line_count} lines")

    def load_config_variables(self, config: RootConfig, target_config: "EffectiveTargetConfig"):
        """
        Load and merge configuration for global and container-specific keywords and settings.
        Called on initialization and when reloading config.

        Args:
            config: Global configuration object
            target_config: ContainerConfig or SwarmServiceConfig
        """
        self.config = config
        self.target_config = target_config
        self.target_config_dict = self.target_config.model_dump(exclude_none=True) if self.target_config else {}

        # Merge global and target-specific keywords
        self.keywords = self.target_config_dict.get("keywords", [])
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
                self.logger.debug(f"{self.target_name}: Found pattern: {pattern} with {count} matches of {self.line_count} lines. {round(count / self.line_count * 100, 2)}%")
                self.valid_pattern = True
                self.start_flush_thread_if_needed()
        if self.line_count >= self.line_limit and not self.patterns:
            self.logger.info(f"{self.target_name}: No pattern found in logs after {self.line_limit} lines. Mode: single-line")

        self.waiting_for_pattern = False

    def process_line(self, line: str):
        """        
        Entry point for processing a single log line. 
        If multi-line mode is off or no pattern is detected, processes as single line; 
        otherwise, processes as part of a multi-line entry.
        """
        clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)  # Remove ANSI color codes
        if self.multi_line_mode is False:
            self._search_and_process(clean_line)
        else:
            if self.line_count < self.line_limit:
                self._find_starting_pattern(clean_line)
            if self.valid_pattern is True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_process(clean_line)

    def start_flush_thread_if_needed(self):
        """Start the buffer flush thread if multi-line mode is enabled and a valid pattern is detected."""
        def check_flush():
            """
            Background thread: flushes buffer after one second passed since last log line.
            """
            self.logger.debug(f"Flush Thread started for {self.target_name}.")
            self.flush_thread_stopped.clear()
            while not self.target_stop_event.is_set():
                # Wait for new line event to be set but check every 60 seconds if the target is stopped
                self.new_line_event.wait(60)
                if not self.new_line_event.is_set():
                    continue
                # Check if buffer needs to be flushed after one second passed since last log line
                while True:
                    time.sleep(1)
                    with self.lock_buffer:
                        if (time.time() - self.log_stream_last_updated > 1) or self.target_stop_event.is_set():
                            if self.buffer:
                                self._handle_and_clear_buffer()
                                self.new_line_event.clear()
                            break
            self.flush_thread_stopped.set()
            self.logger.debug(f"Flush Thread stopped for {self.target_name}")

        if not self.target_stop_event.is_set() and self.multi_line_mode and self.valid_pattern and self.flush_thread_stopped.is_set():
            self.flush_thread = Thread(target=check_flush, daemon=True)
            self.flush_thread.start()

    def _handle_and_clear_buffer(self):
        """Flush buffer and process its contents as a single log entry."""
        log_entry = "\n".join(self.buffer)
        self.buffer.clear()
        if log_entry.strip():
            self._search_and_process(log_entry)
        else:
            self.logger.debug(f"Buffer for {self.target_name} was empty, nothing to process.")

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


    def _search_keyword(self, log_line: str, keyword_dict: dict, ignore_keyword_time: bool = False) -> str | tuple | None:
        """
        Search for keyword or regex in log_line. Enforce notification cooldown unless ignore_keyword_time is True.
        For keywords with trigger_on config, matches are accumulated and only trigger
        when the threshold count is reached within the timeframe.
        Returns:
            str or None: The matched keyword/regex or None if no match, on cooldown, or threshold not reached
        """
        def get_keyword_setting(key: str, default: Any = None) -> Any:
            if keyword_dict.get(key) is not None:
                return keyword_dict[key]
            elif self.target_config_dict.get(key, None) is not None:
                return self.target_config_dict[key]
            return default

        def make_group_key(items: tuple[dict]) -> tuple:
            return tuple[str, ...](
                f"{key}: {val}"for d in items for key, val in d.items()
            )

        trigger_cooldown = get_keyword_setting("trigger_cooldown", 10)
        regex_case_sensitive = get_keyword_setting("regex_case_sensitive", False)
        trigger_on = keyword_dict.get("trigger_on") if not ignore_keyword_time else None

        if regex := keyword_dict.get("regex"):
            if ignore_keyword_time or not self.keyword_tracker.is_on_cooldown(regex, trigger_cooldown):
                match = re.search(regex, log_line, re.IGNORECASE if not regex_case_sensitive else 0)
                if match:
                    if self.keyword_tracker.record_match(regex, trigger_on):
                        hide_pattern = get_keyword_setting("hide_full_regex", False)
                        return "Regex-Pattern" if hide_pattern else f"Regex: {regex}"
        elif keyword := keyword_dict.get("keyword"):
            if ignore_keyword_time or not self.keyword_tracker.is_on_cooldown(keyword, trigger_cooldown):
                if keyword.lower() in log_line.lower():
                    if self.keyword_tracker.record_match(keyword, trigger_on):
                        return keyword
        elif all_of := keyword_dict.get("all_of"):
            key = make_group_key(all_of)
            if ignore_keyword_time or not self.keyword_tracker.is_on_cooldown(key, trigger_cooldown):
                all_matched = all(
                    item["keyword"].lower() in log_line.lower() if item.get("keyword")
                    else bool(re.search(item["regex"], log_line, re.IGNORECASE if not regex_case_sensitive else 0))
                    for item in all_of
                )
                if all_matched and self.keyword_tracker.record_match(key, trigger_on):
                    return key
        else:
            self.logger.error(f"No keyword or regex found for {keyword_dict}")
        return None

    def _search_and_process(self, log_line: str):
        """
        Search for keywords/regex in log_line and collect the keyword settings of all found keywords. 
        If a keyword is found, trigger notification and/or get attachment, container action, OliveTin action, etc.
        """
        keywords_found = []
        keyword_level_config = {}
        target_merge_matches = self.target_config.merge_matches
        
        # Search for configured keywords and collect their settings
        for keyword_dict in self.keywords:
            found = self._search_keyword(log_line, keyword_dict)
            if found:
                merge_matches = keyword_dict.get("merge_matches", target_merge_matches)
                if merge_matches is True:
                    # last override first
                    keyword_level_config = merge_with_precedence(
                        precedence=keyword_dict,
                        fallback=keyword_level_config,
                        list_union=True,
                        dict_merge=True,
                    )
                    keywords_found.append(found)
                else:
                    self._process_log_match(log_line=log_line, keyword_level_config=keyword_dict, keywords_found=[found])
        
        if keywords_found:
            self._process_log_match(log_line, keyword_level_config, keywords_found)
            
    def _process_log_match(self, log_line: str, keyword_level_config: dict, keywords_found: list):
        # When an ignored keyword is found, the log line gets ignored and the function returns
        ignored = cast(list[dict], (keyword_level_config.get("ignore_keywords") or []) + (self.target_config_dict.get("ignore_keywords") or []))
        for keyword in ignored:
            ignored_match = self._search_keyword(log_line, keyword, ignore_keyword_time=True)
            if ignored_match:
                self.logger.debug(f"Keyword(s) '{keywords_found}' found in '{self.target_name}' but ignored because ignored keyword '{ignored_match}' was found")
                return
        trigger_context = merge_trigger_context(keyword_level_config, self.target_config_dict)
        formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
        k = "keyword was found" if len(keywords_found) == 1 else "keywords were found"
        self.logger.info(f"The following {k} in {self.target_name}: {keywords_found}."
                    + (f" (A Log FIle will be attached)" if trigger_context.get("attach_logfile") else "")
                    + f"{formatted_log_entry}"
                    )

        notification_context = NotificationContext(
            notification_type=NotificationType.LOG_MATCH,
            target_name=self.target_name,
            monitor_type=self.monitor_type,
            source_metadata=self.monitored_target.get_metadata(),
            keywords_found=keywords_found,
            log_line=log_line,
            regex=keyword_level_config.get("regex"),
            hostname=self.monitored_target.hostname,
            host_identifier=self.monitored_target.host_identifier,
            trigger_on=keyword_level_config.get("trigger_on"),
        )
        process_trigger(
            logger=self.logger,
            config=self.config,
            trigger_context=trigger_context,
            monitored_target=self.monitored_target,
            notification_context=notification_context,
        )

    def _tail_logs(self, lines=100):
        """Tail logs from the monitored target."""
        return self.monitored_target.get_log_tail(lines=lines)
