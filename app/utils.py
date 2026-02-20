from dataclasses import dataclass
import logging
import os


logger = logging.getLogger(__name__)


@dataclass
class LogAttachment:
    content: str
    file_name: str


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


def merge_trigger_context(precedence: dict, fallback: dict) -> dict:
    """Wrapper that applies schema keys from ModularSettings."""
    from config.models.base import TriggerActionsBase
    possible_keys = tuple(TriggerActionsBase.model_fields.keys())
    return merge_with_precedence(precedence, fallback, keys=possible_keys, list_union=True, dict_merge=True)


def merge_defaults(precedence: dict, fallback: dict) -> dict:
    """Merge defaults with precedence."""
    from config.models.base import RootDefaultsConfig
    possible_keys = tuple(RootDefaultsConfig.model_fields.keys())
    return merge_with_precedence(precedence, fallback, keys=possible_keys, list_union=True, dict_merge=True)


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