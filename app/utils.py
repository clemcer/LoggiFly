import time
import logging
from config.config_model import ModularSettings

logger = logging.getLogger(__name__)

def cleanup_stale_action_cooldowns(
    action_cooldowns: dict,
    max_age_seconds: int = 86400,  # 24 hours default
    size_threshold: int = 1000      # Cleanup when dict has >1000 containers
) -> None:
    """
    Remove action cooldown entries older than max_age_seconds.
    Only runs if dict size exceeds threshold (lazy cleanup).
    
    Args:
        action_cooldowns: The nested dict {container: {action: timestamp}}
        max_age_seconds: Remove entries older than this (default 24h)
        size_threshold: Only cleanup if dict has this many containers
    """
    # Only run cleanup if dict is getting large
    if len(action_cooldowns) < size_threshold:
        return
    now = time.time()
    cutoff_time = now - max_age_seconds
    # Find stale containers (all actions are old)
    stale_containers = []
    for container, actions in action_cooldowns.items():
        # Check if ALL actions for this container are stale
        if all(timestamp < cutoff_time for timestamp in actions.values()):
            stale_containers.append(container)
    # Remove stale containers
    for container in stale_containers:
        del action_cooldowns[container]
    # Also cleanup stale individual actions within containers
    for container, actions in action_cooldowns.items():
        stale_actions = [action for action, timestamp in actions.items() if timestamp < cutoff_time]
        for action in stale_actions:
            del actions[action]


def parse_action_target(action: str, container_name: str) -> tuple:
    action_parts = action.split("@")
    if len(action_parts) == 1:
        action_name = action_parts[0].strip().lower()
        container_name = container_name
    elif len(action_parts) == 2:
        action_name = action_parts[0].strip().lower()
        container_name = action_parts[1].strip()
    else:
        logger.error(f"Invalid action syntax: {action}")
        return None, None
    return action_name, container_name


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
            # elif dict_merge and isinstance(p_val, dict) and isinstance(f_val, dict):
            #     val = merge_with_precedence(p_val, f_val, list_union=list_union, dict_merge=dict_merge)
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
