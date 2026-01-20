import re
from typing import Any
import logging

from constants import MonitorType, SUPPORTED_CONTAINER_ACTIONS, SUPPORTED_CONTAINER_EVENTS


def validate_regex(v):
    """
    Validate a regex pattern by attempting to compile it.
    """
    try:
        re.compile(v)
    except re.error as e:
        return False 
    return True


def get_kw_or_rgx(item):
    """
    Extract the keyword, regex, or keyword_group from a config item for error reporting.
    """
    if isinstance(item, dict):
        if "keyword" in item:
            return f"keyword: '{item['keyword']}'"
        elif "regex" in item:
            return f"regex: '{item['regex']}'"
        elif "keyword_group" in item:
            return f"keyword_group: '{item['keyword_group']}'"
    return "unknown"

def validate_keywords(keywords: list[Any], monitor_type: MonitorType) -> list[Any]:
    converted = []
    for item in keywords:
        if isinstance(item, dict):
            keys = list(item.keys())
            # Validate required keys
            if "keyword" in item:
                item["kind"] = "keyword"
            elif "regex" in item:
                if not validate_regex(item["regex"]):
                    raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: Invalid regex.")
                item["kind"] = "regex"
            elif "keyword_group" in item:
                if not isinstance(item["keyword_group"], list):
                    raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword_group' as a list.")
                item["kind"] = "keyword_group"
            else:
                raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword', 'regex' or 'keyword_group' as a key.")
            # Validate and convert fields
            for key in keys:
                if key == "container_action":
                    valid, error = is_valid_container_action(item[key], monitor_type=monitor_type)
                    if not valid:
                        raise ValueError(f"Error in config in field {get_kw_or_rgx(item)}: Invalid action: {error}")
                if isinstance(item[key], int):
                    item[key] = str(item[key])
            converted.append(item)
        else:
            try:
                converted.append(str(item))
            except ValueError:
                raise ValueError(f"Error in config in field 'keywords': '{item}' is not a string.")
    return converted


def validate_container_events(container_events: list[Any], monitor_type: MonitorType) -> list[Any]:
    converted = []
    for item in container_events:
        if isinstance(item, str):
            if item.strip() not in SUPPORTED_CONTAINER_EVENTS:
                raise ValueError(f"Error in config in field 'container_events': '{item}' is not a valid event. Valid events are: {SUPPORTED_CONTAINER_EVENTS}")
            converted.append({
                "event": item.strip(),
            })
        elif isinstance(item, dict):
            for key in item.keys():
                if key == "container_action":
                    valid, error = is_valid_container_action(item[key], monitor_type=monitor_type)
                    if not valid:
                        raise ValueError(f"Error in config in field 'container_events': Invalid action ('{item[key]}') for event '{item['event']}': {error}")
                if isinstance(item[key], int):
                    item[key] = str(item[key])
            converted.append(item)
        else:
            raise ValueError(f"Error in config in field 'container_events': '{item}' is not a string or dict.")
    return converted


def is_valid_container_action(value, monitor_type: MonitorType) -> tuple[bool, str]:
    if monitor_type == MonitorType.SWARM:
        if len(value.split('@')) < 2:
            return False, "container_actions on swarm services are not allowed. Action must be in the format 'action@container_name'"
    elif monitor_type == MonitorType.CONTAINER:
        pass
    else:
        return False, "Container Action not allowed for monitor type: " + monitor_type.value
    if not isinstance(value, str):
        return False, "container action must be a string"
    if not 0 < len(value.split('@')) < 3:
        return False, "container action must be in the format 'action@hostname'"
    if value.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
        return False, "container action must be one of " + ", ".join(SUPPORTED_CONTAINER_ACTIONS)

    return True, ""


def validate_action_cooldown(v):
    """
    Validate action cooldown value with minimum threshold enforcement.
    """
    if v is None:
        return None
    try:
        v = int(v)
    except Exception as e:
        raise ValueError(f"Action cooldown must be an integer. {e}")
    if v < 10:
        logging.warning("Action cooldown must be at least 10 seconds. Setting to 10 seconds")
        return 10
    return v

def validate_olivetin_arguments(arguments: list[Any]) -> list[Any] | None:
    filtered_args = []
    for arg in arguments:
        if not isinstance(arg, dict) or "name" not in arg or "value" not in arg:
            raise ValueError(f"OliveTin Action: arguments must have name and value: '{arg}'. Must be a dictionary with 'name' and 'value' keys.")
        for key, value in arg.items():
            try:
                value = str(value)
            except ValueError:
                raise ValueError(f"OliveTin Action: arguments value must be a string. ({key}: {value})") # TODO: test this
            arg[key] = value
        filtered_args.append(arg)
    return filtered_args


def validate_and_filter_olivetin_actions(data: dict) -> dict:
    if not data:
        return data
    if "olivetin_actions" in data and isinstance(data["olivetin_actions"], list):
        for action in data["olivetin_actions"]:
            if not isinstance(action, dict) or "id" not in action:
                raise ValueError("OliveTin Action: Must be a dictionary with an 'id' key.")
            action["id"] = str(action["id"])
    if data.get("olivetin_action_id"):
        data.setdefault("olivetin_actions", []).append({
            "id": data["olivetin_action_id"],
        })
        data.pop("olivetin_action_id")
    return data


def validate_ntfy_actions(actions: list[Any]) -> list[Any]:       
    if len(actions) > 3:                                          
        raise ValueError(f"Ntfy actions: maximum 3 allowed, got {len(actions)}")                                                  
    return actions


def generate_id_for_policies(data: Any) -> Any:
    if not data:
        return data
    if isinstance(data, dict):
        for idx, policy in enumerate(data.get("policies", [])):
            if policy.get("id") is None:
                policy["id"] = f"policy_{idx}"
        for idx, overlay in enumerate(data.get("overlays", [])):                                        
            if overlay.get("id") is None:                 
                overlay["id"] = f"overlay_{idx}"          
    return data


def validate_shorthand_or_match(data: dict, shorthands: list[str], match_key: str = "match") -> dict:
    if isinstance(data, dict):
        has_shorthand = any(data.get(shorthand) is not None for shorthand in shorthands)
        has_match = data.get(match_key) is not None
        if has_shorthand and has_match:
            raise ValueError(f"Cannot use both {shorthands} shorthand and {match_key} block. Use one or the other.")
    return data