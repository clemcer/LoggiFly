from dataclasses import dataclass
import logging
import os
from threading import Lock
import time
from typing import Literal


logger = logging.getLogger(__name__)


@dataclass
class LogAttachment:
    content: str
    file_name: str


class TriggerTracker:
    """
    Thread-safe tracker for trigger match state.
    Use for both log matches (line_processor.py) and container events (docker_monitoring/monitor.py)
    Handles both simple cooldown (single last-trigger timestamp) and
    threshold-based triggering (sliding window of match timestamps).
    """

    def __init__(self, logger, trigger_type: Literal["keyword", "container_event"]):
        self.logger = logger
        self._lock = Lock()
        self._last_trigger: dict[str | tuple, float] = {}
        self._match_history: dict[str | tuple, list[float]] = {}
        self._trigger_type = trigger_type

    def is_on_cooldown(self, key: str | tuple, cooldown: int) -> bool:
        """Check if the keyword is still within its trigger_cooldown period."""
        with self._lock:
            last = self._last_trigger.get(key, 0)
            return (time.time() - last) < cooldown

    def record_match(self, key: str | tuple, trigger_on: dict | None) -> bool:
        """
        Record a trigger match (log match or container event)and determine whether to trigger.

        Without trigger_on: triggers immediately (returns True) and stores the current time.
        With trigger_on: adds the timestamp to a sliding window and only triggers
        when `count` matches have occurred within the last `timeframe` seconds.
        On trigger the match history is cleared so the count starts fresh.

        Returns:
            True if the trigger should fire, False if the match was recorded
            but the threshold has not been reached yet.
        """
        now = time.time()
        with self._lock:
            if trigger_on is None:
                self._last_trigger[key] = now
                return True

            count = trigger_on["count"]
            timeframe = trigger_on["timeframe"]
            assert isinstance(count, int) and isinstance(timeframe, int), "count and timeframe must be integers"

            history = self._match_history.setdefault(key, [])
            history.append(now)

            # Prune timestamps outside the sliding window
            cutoff = now - timeframe
            history[:] = [t for t in history if t > cutoff]

            if len(history) >= count:
                self._last_trigger[key] = now
                history.clear()
                return True
            self.logger.debug(f"{self._trigger_type} '{key}' matched {len(history)} times in the last {timeframe} seconds. {count - len(history)} more matches needed to trigger.")

            return False



def get_env_var(key: str, prefix: str = "LOGGIFLY_", fallback_value: str | None = None) -> str | None:
    """
    Look up an env var, checking the prefixed name first (e.g. LOGGIFLY_FOO before FOO).
    The prefixed var can be set to an empty string to explicitly suppress the unprefixed one (in case of any conflicts).
    """
    val = os.getenv(f"{prefix}{key}")
    if val is not None:
        if not val.strip():
            return None
        return val
    val = os.getenv(key)
    if val is not None:
        return val
    return fallback_value

def is_true_env_var(val: str | None) -> bool:
    return isinstance(val, str) and val.strip().lower() == "true"


def _union_lists(first: list, second: list) -> list:
    """Return union preserving order with `first` items first."""
    merged = list(first)
    for item in second:
        if item not in merged:
            merged.append(item)
    return merged


def merge_with_precedence(
    precedence: dict | None,
    fallback: dict | None,
    *,
    keys: list[str] | tuple[str, ...] | None = None,
    list_union: bool = True,
    dict_merge: bool = True,
) -> dict:
    """
    Generic precedence merge helper used for modular settings and notifications.
    If keys are provided, only these keys are considered (maintains schema alignment).
    """
    precedence = precedence or {}
    fallback = fallback or {}
    considered_keys = keys if keys is not None else set(precedence.keys()) | set(fallback.keys())
    merged: dict = {}

    for key in considered_keys:
        p_val = precedence.get(key)
        f_val = fallback.get(key)

        if p_val is None:
            val = f_val
        else:
            if list_union and isinstance(p_val, list) and isinstance(f_val, list):
                val = _union_lists(f_val, p_val) # in v2 last override first
            elif dict_merge and isinstance(p_val, dict) and isinstance(f_val, dict):
                val = merge_with_precedence(p_val, f_val, list_union=list_union, dict_merge=dict_merge)
            else:
                val = p_val

        if val is not None:
            merged[key] = val

    return merged


def merge_config_levels(precedence: dict, fallback: dict, possible_keys: list[str] | tuple[str, ...] | None = None) -> dict:
    return merge_with_precedence(
        precedence, 
        fallback, 
        keys=possible_keys, 
        list_union=True, 
        dict_merge=True,
    )
    

def merge_trigger_context(precedence: dict, fallback: dict) -> dict:
    """Wrapper that applies schema keys from ModularSettings."""
    from config.models.base import TriggerActionsBase
    possible_keys = tuple(TriggerActionsBase.model_fields.keys())
    return merge_config_levels(precedence, fallback, possible_keys)


def merge_defaults(precedence: dict, fallback: dict) -> dict:
    """Merge defaults with precedence."""
    from config.models.base import RootDefaultsConfig
    possible_keys = tuple(RootDefaultsConfig.model_fields.keys())
    return merge_config_levels(precedence, fallback, possible_keys)


def convert_to_int(val, fallback_value: int = 0, min_value: int = 0) -> int:
    if val is None:
        return fallback_value
    try:
        val = int(val)
        if val < min_value:
            return fallback_value
        return val
    except (ValueError, TypeError):
        return fallback_value