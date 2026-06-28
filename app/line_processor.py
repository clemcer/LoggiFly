import re
import time
from typing import Any
import threading
from threading import Thread, Lock
from dataclasses import dataclass

from constants import (
    COMPILED_STRICT_PATTERNS,
    COMPILED_FLEX_PATTERNS,
    NotificationType,
)
from notification_formatter import NotificationContext
from utils import merge_trigger_context, merge_config_levels, TriggerTracker, make_buffer_match_key
from trigger import process_trigger
from config.models import RootConfig
from monitoring import MonitoredTarget, EffectiveTargetConfig

@dataclass
class LogMatchContext:
    trigger_context: dict
    keyword_level_config: dict
    log_line: str
    keywords_found: list


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

        # buffer for buffer_seconds setting
        self.log_match_buffer = {}
        self.log_match_buffer_lock = Lock()

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


    ############################################################################
    # Below is everything related to keyword matching, filtering and processing
    ############################################################################

    def _get_keyword_setting(self, keyword_dict: dict, key: str, default: Any = None) -> Any:
        if keyword_dict.get(key) is not None:
            return keyword_dict[key]
        elif self.target_config_dict.get(key, None) is not None:
            return self.target_config_dict[key]
        return default

    def _match_keyword(self, log_line: str, keyword_dict: dict) -> str | tuple | None:
        """
        Search for keyword or regex in log_line.

        Returns:
            str or tuple or None: The matched keyword/regex display value, or None if no match.
        """
        regex_case_sensitive = self._get_keyword_setting(keyword_dict, "regex_case_sensitive", False)
        if regex := keyword_dict.get("regex"):
            match = re.search(regex, log_line, re.IGNORECASE if not regex_case_sensitive else 0)
            if match:
                hide_pattern = self._get_keyword_setting(keyword_dict, "hide_full_regex", False)
                return "Regex-Pattern" if hide_pattern else f"Regex: {regex}"
        elif keyword := keyword_dict.get("keyword"):
            if keyword.lower() in log_line.lower():
                return keyword
        elif all_of := keyword_dict.get("all_of"):
            all_matched = all(
                item["keyword"].lower() in log_line.lower() if item.get("keyword")
                else bool(re.search(item["regex"], log_line, re.IGNORECASE if not regex_case_sensitive else 0))
                for item in all_of
            )
            if all_matched:
                return self._keyword_tracker_key(keyword_dict)
        else:
            self.logger.error(f"No keyword, regex or all_of found for {keyword_dict}")
        return None

    def _keyword_tracker_key(self, keyword_dict: dict) -> str | tuple:
        if regex := keyword_dict.get("regex"):
            return regex
        if keyword := keyword_dict.get("keyword"):
            return keyword
        if all_of := keyword_dict.get("all_of"):
            return tuple(
                f"{key}: {val}" for item in all_of for key, val in item.items()
            )
        raise AssertionError("keyword_dict has no keyword, regex or all_of")
    

    def _is_ignored_match(self, ignore_keywords: list, log_line) -> bool:
        for keyword in ignore_keywords:
            ignored_match = self._match_keyword(log_line, keyword)
            if ignored_match:
                self.logger.debug(f"ignore_keywords '{ignored_match}' was found in log line {log_line[:75]}...")
                return True
        return False

    def _is_on_cooldown(self, keyword_dict, tracker_key) -> bool:
        if self.keyword_tracker.is_on_cooldown(
            tracker_key, 
            self._get_keyword_setting(keyword_dict, "trigger_cooldown", 10)
            ):
            return True
        return False
    
    def _passes_trigger_on(self, keyword_dict, tracker_key) -> bool:
        if not self.keyword_tracker.record_trigger_on_match(
            tracker_key,
            keyword_dict.get("trigger_on")
            ):
            return False 
        return True

    def _search_and_process(self, log_line: str):
        """
        Search for keywords/regex in log_line and collect the keyword settings of all found keywords. 
        If a keyword is found, trigger notification and/or get attachment, container action, OliveTin action, etc.
        """

        keywords_found = []
        keyword_level_config = {}
        
        # Search for configured keywords and collect their settings
        for keyword_dict in self.keywords:
            tracker_key = self._keyword_tracker_key(keyword_dict)
            buffer_seconds = self._get_keyword_setting(keyword_dict, "buffer_seconds", 0)
            should_buffer = isinstance(buffer_seconds, int) and buffer_seconds > 0

            # Cooldown of keywords with buffer_seconds are checked separately and not always
            if not should_buffer and self.keyword_tracker.is_on_cooldown(
                tracker_key, 
                self._get_keyword_setting(keyword_dict, "trigger_cooldown", 10)
                ):
                continue

            found = self._match_keyword(log_line, keyword_dict)
            if found:
                # Treat keywords with buffer_seconds setting separately
                if should_buffer:

                    if self._is_ignored_match(self.target_config_dict.get("ignore_keywords") or [], log_line):
                        return
                    if self._is_ignored_match(keyword_dict.get("ignore_keywords") or [], log_line):
                        continue
                    
                    if self._try_append_to_existing_buffer(keyword_dict, log_line):
                        self.logger.debug(f"Keyword: {found} going into buffer")
                        continue
                    
                    # for first match in buffer we check cooldown and trigger_on
                    if self._is_on_cooldown(keyword_dict, tracker_key):
                        continue
                    if not self._passes_trigger_on(keyword_dict, tracker_key):
                        continue

                    lms = LogMatchContext(
                        trigger_context=merge_trigger_context(keyword_dict, self.target_config_dict),
                        keyword_level_config=keyword_dict,
                        keywords_found=[found],
                        log_line=log_line
                        )
                    # mark as triggered when first entry is added to buffer
                    self.keyword_tracker.restart_trigger_cooldown(tracker_key)
                    self.logger.info(f"'{found}' was found in a log line but has 'buffer_seconds' configured. Log line will go into buffer and only trigger in {buffer_seconds}s")
                    self._start_match_buffer(lms)
                    continue
                
                if self._is_ignored_match(self.target_config_dict.get("ignore_keywords") or [], log_line):
                    return
                if self._is_ignored_match(keyword_dict.get("ignore_keywords") or [], log_line):
                    continue

                if not self._passes_trigger_on(keyword_dict, tracker_key):
                    continue

                self.keyword_tracker.restart_trigger_cooldown(tracker_key)
                merge_matches = self._get_keyword_setting(keyword_dict, "merge_matches", False)
                if merge_matches:
                    # with merge_matches enabled, all found keywords only trigger once
                    # keyword level settings are merged (last override first)
                    keyword_level_config = merge_config_levels(
                        precedence=keyword_dict,
                        fallback=keyword_level_config,
                    )
                    keywords_found.append(found)
                else:
                    trigger_context = merge_trigger_context(keyword_dict, self.target_config_dict)
                    lms = LogMatchContext(
                        trigger_context=trigger_context,
                        keyword_level_config=keyword_dict,
                        keywords_found=[found],
                        log_line=log_line
                        )
                    self._process_log_match(lms)
        
        if keywords_found:
            trigger_context = merge_trigger_context(keyword_level_config, self.target_config_dict)
            lms = LogMatchContext(
                trigger_context=trigger_context,
                keyword_level_config=keyword_level_config,
                keywords_found=keywords_found,
                log_line=log_line
                )
            self._process_log_match(lms)
    
    def _try_append_to_existing_buffer(self, keyword_level_config: dict, log_line) -> bool:
        key = make_buffer_match_key(keyword_level_config)
        with self.log_match_buffer_lock:
          if key not in self.log_match_buffer:
              return False
          self.log_match_buffer[key].append(log_line)
          return True
        
    def _start_match_buffer(self, lms: LogMatchContext):
        bs = lms.trigger_context["buffer_seconds"]
        key = make_buffer_match_key(lms.keyword_level_config)
        
        def clear():
            self.logger.debug(f"Clear log match buffer called. clearing in {bs}")
            stopped = self.target_stop_event.wait(bs)
            if stopped:
                self.logger.debug("Flushing log match buffer (from buffer_seconds) because monitoring stopped")
            with self.log_match_buffer_lock:
                l = self.log_match_buffer.pop(key)
                if not l:
                    return
            lms.log_line = "\n".join(l)
            self._process_log_match(lms, len(l))

        with self.log_match_buffer_lock:
            if not self.log_match_buffer.get(key):
                self.log_match_buffer[key] = [lms.log_line]
                clear_thread = Thread(target=clear, daemon=True)
                clear_thread.start()
            else:
                self.log_match_buffer[key].append(lms.log_line)
        return True

    def _process_log_match(self, lms: LogMatchContext, buffer_count: int = 1):
        # TODO: maybe change logged message for buffered match?
        bs = lms.trigger_context.get('buffer_seconds')
        formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(lms.log_line.splitlines()) + "\n   -----------------------"
        k = "keyword was found" if len(lms.keywords_found) == 1 else "keywords were found"
        k = k + f" {buffer_count} time{'s' if isinstance(buffer_count, int) and buffer_count > 1 else ''} in {bs}s" if bs else ""
        self.logger.info(f"The following {k} in {self.target_name}: {lms.keywords_found}."
                    + (f" (A Log FIle will be attached)" if lms.trigger_context.get("attach_logfile") else "")
                    + f"{formatted_log_entry}"
                    )

        notification_context = NotificationContext(
            notification_type=NotificationType.LOG_MATCH,
            target_name=self.target_name,
            monitor_type=self.monitor_type,
            source_metadata=self.monitored_target.get_metadata(),
            keywords_found=lms.keywords_found,
            log_line=lms.log_line,
            regex=lms.keyword_level_config.get("regex"),
            hostname=self.monitored_target.hostname,
            host_identifier=self.monitored_target.host_identifier,
            trigger_on=lms.keyword_level_config.get("trigger_on"),
            buffer_count=buffer_count,
            buffer_seconds=bs
        )
        process_trigger(
            logger=self.logger,
            config=self.config,
            trigger_context=lms.trigger_context,
            monitored_target=self.monitored_target,
            notification_context=notification_context,
        )

    def _tail_logs(self, lines=100):
        """Tail logs from the monitored target."""
        return self.monitored_target.get_log_tail(lines=lines)
