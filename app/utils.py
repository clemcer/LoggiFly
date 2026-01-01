import time
import logging
from config.config_model import ModularSettings

logger = logging.getLogger(__name__)

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
    no_list_union: list[str] = [],
    dict_merge: bool = False,
) -> dict:
    """
    Generic precedence merge helper used for modular settings and notifications.

    Rules:
    - `None` in precedence means "not set" → fallback is kept.
    - Scalars: first non-None wins.
    - Lists: union with precedence items first (order preserved, duplicates removed) when `list_union` is True;
      otherwise precedence replaces.
    - Dicts: shallow merge, precedence overrides; nested dicts merged recursively.
    - Keys: if provided, only these keys are considered (maintains schema alignment).
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
            if list_union and isinstance(p_val, list) and isinstance(f_val, list) and key not in no_list_union:
                val = _union_lists(p_val, f_val)
            elif dict_merge and isinstance(p_val, dict) and isinstance(f_val, dict):
                val = merge_with_precedence(p_val, f_val, list_union=list_union, dict_merge=dict_merge)
            else:
                val = p_val

        if val is not None:
            merged[key] = val

    return merged


def merge_modular_settings(precedence: dict, fallback: dict) -> dict:
    """Wrapper that applies schema keys from ModularSettings."""
    possible_keys = tuple(ModularSettings.model_fields.keys())
    # i dont think we want to merge lists of ntfy_actions... but excluded_keywords we do probably want (keeps old behavior)
    return merge_with_precedence(precedence, fallback, keys=possible_keys, list_union=True, no_list_union=["ntfy_actions"])


def convert_to_int(val, fallback_value: int = 0) -> int:
    try:
        val = int(val)
        if val < 0:
            return fallback_value
        return val
    except ValueError:
        return fallback_value