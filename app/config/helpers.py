import re
from typing import Any
import logging
import os
from pydantic import ValidationError

from constants import MonitorType, SUPPORTED_CONTAINER_ACTIONS, SUPPORTED_CONTAINER_EVENTS

def strict_config_validation() -> bool:
    return os.getenv("LOGGIFLY_STRICT_CONFIG", "true").lower() == "true" # TODO: think about default

def handle_error(message: str, consequence: str | None = None):
    if strict_config_validation():
        raise ValueError(message)
    else:
        logging.warning("Ignoring Error in config: " + message + (f". {consequence}" if consequence else ""))


def format_pydantic_error(e: ValidationError) -> str:
    """
    Format Pydantic validation errors for user-friendly display.
    """
    if not isinstance(e, ValidationError):
        return str(e)
    error_messages = []
    for error in e.errors():
        location = ".".join(map(str, error["loc"]))
        msg = error["msg"]
        # msg = msg.split("[")[0].strip()  # Remove technical details in brackets
        error_messages.append(f"Error in config in field '{location}': {msg}")
    return "\n".join(error_messages)

def stringify_numbers(data: dict) -> dict:                            
    """Recursively convert ints/floats to strings in a config dict.                                            
                                                        
    Safe because Pydantic coerces strings back to int/float where needed,                                 
    but won't coerce int to str.                        
    """                                                 
    if isinstance(data, dict):                          
        return {k: stringify_numbers(v) for k, v in data.items()}                                           
    elif isinstance(data, list):                        
        return [stringify_numbers(item) for item in data]                                                   
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        return str(data)                                
    else:                                               
        return data


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
    for idx, item in enumerate(keywords):
        if isinstance(item, dict):
            keys = list(item.keys())
            # Validate required keys
            if len(set(keys) & {"keyword", "regex", "keyword_group"}) != 1:
                handle_error(f"keywords.{idx}: You have to set exactly one of 'keyword', 'regex' or 'keyword_group' as a key: {item}.")
                continue
            if "keyword" in item:
                kind = "keyword"
            elif "regex" in item:
                if not validate_regex(item["regex"]):
                    handle_error(f"keywords.{idx}.regex: Invalid regex: {item['regex']}.")
                    continue
                kind = "regex"
            elif "keyword_group" in item:
                if not isinstance(item["keyword_group"], list):
                    handle_error(f"keywords.{idx}.keyword_group: You have to set 'keyword_group' as a list: {item['keyword_group']}.")
                    continue
                kind = "keyword_group"
            else:
                handle_error(f"keywords.{idx}: You have to set 'keyword', 'regex' or 'keyword_group' as a key: {item}.")
                continue
            # Validate and convert fields
            skip_key = False
            for key in keys:
                if key == "container_action":
                    valid, error = is_valid_container_action(item[key], monitor_type=monitor_type)
                    if not valid:
                        handle_error(f"keywords.{idx}.{key}: Invalid action: {error}")
                        skip_key = True
            if skip_key:
                continue
            converted.append({"kind": kind, **item})
        elif isinstance(item, (str, int)):
            converted.append({"kind": "keyword", "keyword": str(item)})
        else:
            handle_error(f"keywords.{idx}: Invalid type. Must be a string or dict: {item}.")
            continue
    return converted

def validate_simple_keywords(keywords: list[Any], field_name: str) -> list[Any]:
    """
    Validate simple keywords and regex.
    """
    converted = []
    for idx, item in enumerate(keywords):
        if isinstance(item, (str, int)):
            converted.append({
                "keyword": str(item),
            })
        elif isinstance(item, dict):
            if item.get("keyword") and item.get("regex"):
                handle_error(f"{field_name}.{idx}: You can only set 'keyword' or 'regex', not both: {item}")
                continue
            if item.get("keyword"):
                pass
            elif item.get("regex"):
                if not validate_regex(item["regex"]):
                    handle_error(f"{field_name}.{idx}.regex: Invalid regex: {item['regex']}")
                    continue
            else:
                handle_error(f"{field_name}.{idx}: You have to set 'keyword' or 'regex' as a key: {item}")
                continue
            converted.append(item)
        else:
            handle_error(f"{field_name}.{idx}: Invalid type. Must be a string or dict: {item}")
            continue
    return converted

def validate_container_events(container_events: list[Any], monitor_type: MonitorType) -> list[Any]:
    converted = []
    for idx, item in enumerate(container_events):
        if isinstance(item, str):
            if item.strip() not in SUPPORTED_CONTAINER_EVENTS:
                handle_error(f"container_events.{idx}: '{item}' is not a valid event. Valid events are: {SUPPORTED_CONTAINER_EVENTS}")
                continue
            converted.append({
                "event": item.strip(),
            })
        elif isinstance(item, dict):
            if not item.get("event") in SUPPORTED_CONTAINER_EVENTS:
                handle_error(f"container_events.{idx}: '{item}' is not a valid event. Valid events are: {SUPPORTED_CONTAINER_EVENTS}")
                continue
            if item.get("container_action"):
                valid, error = is_valid_container_action(item["container_action"], monitor_type=monitor_type)
                if not valid:
                    handle_error(f"container_events.{idx}: Invalid action ('{item['container_action']}') for event '{item['event']}': {error}")
                    continue # TODO: continue or put value None?
            converted.append(item)
        else:
            handle_error(f"container_events.{idx}: '{item}' is not a string or dict.")
    return converted


def is_valid_container_action(value, monitor_type: MonitorType) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, "container action must be a string"
    if monitor_type == MonitorType.SWARM:
        if len(value.split('@')) < 2:
            return False, "container_actions on swarm services are not allowed. Action must be in the format 'action@container_name'"
    elif monitor_type == MonitorType.CONTAINER:
        pass
    else:
        return False, "Container Action not allowed for monitor type: " + monitor_type.value
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
        handle_error(f"Action cooldown must be an integer. {e}")
        return None
    if v < 10:
        handle_error("Action cooldown must be at least 10 seconds.", "Setting to 10 seconds")
        return 10
    return v

def validate_olivetin_arguments(arguments: list[Any]) -> list[Any] | None:
    filtered_args = []
    for idx, arg in enumerate(arguments):
        if not isinstance(arg, dict) or "name" not in arg or "value" not in arg:
            handle_error(f"olivetin_actions.arguments.{idx}: arguments must have name and value: '{arg}'. Must be a dictionary with 'name' and 'value' keys.")
            continue
        skip_key = False
        for key, value in arg.items():
            try:
                value = str(value)
            except ValueError:
                handle_error(f"olivetin_actions.arguments.{idx}: arguments value must be a string. ({key}: {value})") # TODO: test this
                skip_key = True
            arg[key] = value
        if skip_key:
            continue
        filtered_args.append(arg)
    return filtered_args


def validate_and_filter_olivetin_actions(data: dict) -> dict:
    if not data:
        return data
    if "olivetin_actions" in data and isinstance(data["olivetin_actions"], list):
        for idx, action in enumerate(data["olivetin_actions"]):
            if not isinstance(action, dict) or "id" not in action:
                handle_error(f"olivetin_actions.{idx}: Must be a dictionary with an 'id' key.")
                continue
            action["id"] = str(action["id"])
    if data.get("olivetin_action_id"):
        data.setdefault("olivetin_actions", []).append({
            "id": data["olivetin_action_id"],
        })
        data.pop("olivetin_action_id")
    return data

def validate_ntfy_priority(v):
    """
    Validate and normalize the ntfy priority value. 
    """
    if isinstance(v, str):
        if not v.isdigit():
            options = ["max", "urgent", "high", "default", "low", "min"]
            if v not in options:
                handle_error(f"Ntfy priority:'{v}'. Only 'max', 'urgent', 'high', 'default', 'low', 'min' or integer between 1-5 are allowed.", "Using default: '3'")
                return None
        try:
            v = int(v)
        except ValueError:
            handle_error(f"Ntfy priority: Must be an integer. '{v}' is not allowed.", "Using default: '3'")
            return None
    if isinstance(v, int):
        if not 1 <= int(v) <= 5:
            handle_error(f"Ntfy priority: Must be between 1-5, '{v}' is not allowed.", "Using default: '3'")
            return None
    return v


def validate_ntfy_actions(actions: list[Any]) -> list[dict]:
    possible_actions = ["http", "broadcast", "view"]
    filtered_actions = []
    for idx, raw in enumerate(actions, 1):
        if not isinstance(raw, dict):
            handle_error(f"ntfy_actions.{idx}: action must be a dictionary. You set '{raw}'.")
            continue
        action_type = raw.get("action")
        if not action_type or action_type not in possible_actions:
            handle_error(f"ntfy_actions.{idx}: action must be one of {possible_actions}. You set '{raw}'.")
            continue
        if not raw.get("label"):
            handle_error(f"ntfy_actions.{idx}: label is required. You set '{raw}'.")
            continue
        if action_type in ["http", "view"] and not raw.get("url"):
            handle_error(f"ntfy_actions.{idx}: url is required for action '{raw['action']}'. You set '{raw}'.")
            continue
        if len(filtered_actions) >= 3:
            handle_error(f"ntfy_actions.{idx}: You can only have up to 3 actions.")
            break
        filtered_actions.append(raw)
    return filtered_actions

def generate_id_for_policies(data: Any) -> Any:
    if isinstance(data, dict):
        for idx, policy in enumerate(data.get("policies", [])):
            if policy.get("id") is None:
                policy["id"] = f"policy_{idx}"
        for idx, overlay in enumerate(data.get("overlays", [])):                                        
            if overlay.get("id") is None:                 
                overlay["id"] = f"overlay_{idx}"          
    return data



def convert_shorthand_to_match(data: dict, shorthand_mapping: dict[str, str]) -> dict:                                           
    """                                                            
    shorthand_mapping: {"container_name": "container_names"} or    
                        {"service_name": "service_names", "stack_name": "stack_names"}     
    Raises ValueError if both shorthand and match block are present.
    """                                                            
    shorthands_present = {k: data[k] for k in shorthand_mapping if data.get(k) is not None}                                           
    has_match = data.get("match") is not None
    if not shorthands_present and not has_match:
        raise ValueError(f"You have to set at a shorthand {list(shorthand_mapping.keys())} or a 'match' block. You set '{data}'.")
    if not shorthands_present and has_match:
        return data
    if shorthands_present:
        if has_match:
            raise ValueError(f"Cannot use both {list(shorthands_present.keys())} shorthand and 'match' block.")
        include = {}                                               
        for shorthand, target_field in shorthand_mapping.items():  
            if shorthand in shorthands_present:                    
                include[target_field] = [data.pop(shorthand)]      
        data["match"] = {"include": include}                                                                            
    return data 