import re
from typing import Any
import logging
import os
from pydantic import ValidationError, SecretStr
import yaml
from constants import MonitorType, SUPPORTED_CONTAINER_ACTIONS, SUPPORTED_CONTAINER_EVENTS
from utils import get_env_var


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        """indent lists as well"""
        return super().increase_indent(flow=flow, indentless=False)


def strict_config_validation() -> bool:
    val = get_env_var("STRICT_CONFIG")
    if val is None:
        return True
    return val.lower() == "true" # TODO: think about default


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


def get_pretty_yaml_config(config, top_level_key=None):
    """
    Convert a Pydantic config object to a pretty-printed YAML string.
    
    Args:
        config: Pydantic model instance
        top_level_key: Optional key to wrap the config in
        
    Returns:
        str: Pretty-formatted YAML string
    """
    config_dict = prettify_config_dict(
        config.model_dump(
            exclude_none=True, 
            exclude_defaults=False, 
            exclude_unset=False,
            by_alias=True,
        )
    )
    if top_level_key:
        config_dict = {top_level_key: config_dict}
    return yaml.dump(
        config_dict, 
        Dumper=MyDumper, 
        default_flow_style=False,
        sort_keys=False, 
        indent=2,
        allow_unicode=True
        )


def prettify_config_dict(data, mask_secrets: bool = True):
    """
    Recursively format config dict for display, masking secrets and ordering keys for readability.
    """ 
    _PRIORITY_KEYS = (
        "id", "enabled", "match", "container_name", "service_name", "stack_name",
        "regex", "keyword", "all_of", "container_event", "container_action"
        )
    if isinstance(data, dict):
        priority_keys = [k for k in _PRIORITY_KEYS if k in data]
        if priority_keys:
            rest_keys = [k for k in data.keys() if k not in priority_keys]
            ordered_dict = {k: data[k] for k in priority_keys + rest_keys}
            return {k: prettify_config_dict(v, mask_secrets) for k, v in ordered_dict.items()}
        return {k: prettify_config_dict(v, mask_secrets) for k, v in data.items()}
    elif isinstance(data, list):
        return [prettify_config_dict(item, mask_secrets) for item in data]
    elif isinstance(data, SecretStr):
        return "**********" if mask_secrets else data.get_secret_value()
    else:
        return data


def stringify_numbers(data) -> Any:                            
    if isinstance(data, dict):                          
        return {k: stringify_numbers(v) for k, v in data.items()}                                           
    elif isinstance(data, list):                        
        return [stringify_numbers(item) for item in data]                                                   
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        return str(data)                                
    else:                                               
        return data


def discriminate_keyword_type(v: Any):
    if isinstance(v, dict):
        return next(key for key in ["keyword", "regex", "all_of"] if key in v)
    return next(key for key in ["keyword", "regex", "all_of"] if hasattr(v, key))



# ===============================
# Validation functions
# ===============================

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
    Extract the keyword, regex, or all_of from a config item for error reporting.
    """
    if isinstance(item, dict):
        if "keyword" in item:
            return f"keyword: '{item['keyword']}'"
        elif "regex" in item:
            return f"regex: '{item['regex']}'"
        elif "all_of" in item:
            return f"all_of: '{item['all_of']}'"
    return "unknown"


def validate_keywords(keywords: list[Any]) -> list[Any]:
    converted = []
    for idx, item in enumerate(keywords):
        if isinstance(item, dict):
            keys = list(item.keys())

            if len(set(keys) & {"keyword", "regex", "all_of"}) != 1:
                handle_error(f"keywords.{idx}: You have to set exactly one of 'keyword', 'regex' or 'all_of' as a key: {item}.")
                continue

            if "keyword" in item:
                pass
            elif "regex" in item:
                if not validate_regex(item["regex"]):
                    handle_error(f"keywords.{idx}.regex: Invalid regex: {item['regex']}.")
                    continue
            elif "all_of" in item:
                if not isinstance(item["all_of"], list):
                    handle_error(f"keywords.{idx}.all_of: You have to set 'all_of' as a list: {item['all_of']}.")
                    continue
            else:
                handle_error(f"keywords.{idx}: You have to set 'keyword', 'regex' or 'all_of' as a key: {item}.")
                continue
            converted.append(item)
        elif isinstance(item, (str, int)):
            converted.append({
                "keyword": str(item),
            })
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


def validate_container_events(container_events: list[Any]) -> list[Any]:
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
            converted.append(item)
        else:
            handle_error(f"container_events.{idx}: '{item}' is not a string or dict.")
    return converted


def validate_container_action(value, monitor_type: MonitorType | None) -> str | None:
    if not isinstance(value, str):
        handle_error("container action must be a string")
        return None
    if monitor_type == MonitorType.SWARM:
        if len(value.split('@')) < 2:
            handle_error("container_actions on swarm services are not allowed. Actions under the swarm block must have a target and be in the format 'action@container_name'")
            return None
    elif monitor_type == MonitorType.CONTAINER:
        pass
    else:
        handle_error("container_action not allowed for monitor type: " + (monitor_type.value if isinstance(monitor_type, MonitorType) else "monitor type is not set"))
        return None
    if not 0 < len(value.split('@')) < 3:
        handle_error("container_action must be in the format 'action' or 'action@hostname'")
        return None
    if value.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
        handle_error("container_action must be one of " + ", ".join(SUPPORTED_CONTAINER_ACTIONS))
        return None
    return value


def validate_container_action_cooldown(v):
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
        v = v.strip()
        if not v.isdigit():
            options = ["max", "urgent", "high", "default", "low", "min"]
            if v not in options:
                handle_error(f"Ntfy priority:'{v}'. Only 'max', 'urgent', 'high', 'default', 'low', 'min' or integer between 1-5 are allowed.", "Using default: '3'")
                return 3
            return v
        try:
            v = int(v)
        except ValueError:
            handle_error(f"Ntfy priority: Must be an integer. '{v}' is not allowed.", "Using default: '3'")
            return 3
    if isinstance(v, int):
        if not 1 <= int(v) <= 5:
            handle_error(f"Ntfy priority: Must be between 1-5, '{v}' is not allowed.", "Using default: '3'")
            return 3
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

def validate_trigger_on(v: Any) -> dict | None:
    if v is None:
        return None
    if not isinstance(v, dict):
        handle_error(f"trigger_on: Must be a dictionary with 'count' and 'timeframe' keys. You set '{v}'.")
        return None
    count = v.get("count")
    timeframe = v.get("timeframe")
    if count is None or timeframe is None:
        handle_error(f"trigger_on: count and timeframe are required. You set '{v}'.")
        return None
    try:
        count = int(count)
        timeframe = int(timeframe)
    except ValueError:
        handle_error(f"trigger_on: count and timeframe must be integers. You set '{v}'.")
        return None
    if count < 2:
        handle_error(f"trigger_on: count must be at least 2. You set '{v}'.")
        return None
    if timeframe < 1:
        handle_error(f"trigger_on: timeframe must be at least 1. You set '{v}'.")
        return None
    return {"count": count, "timeframe": timeframe}


def validate_and_generate_ids(data: Any, source_name: str) -> Any:

    def _process_items(items: list[dict], prefix: str, label: str, seen: set[str]):
        # First pass: collect explicit IDs, detect cross-list duplicates
        for item in items:
            item_id = item.get("id")
            if item_id is None:
                continue
            if item_id in seen:
                handle_error(f"Duplicate id found in {label}: {item_id}")
                item.pop("id")
            else:
                seen.add(item_id)
        # Second pass: generate IDs for items that don't have one, avoiding collisions
        counter = 1
        for item in items:
            if item.get("id") is None:
                while f"{prefix}-{counter}" in seen:
                    counter += 1
                item["id"] = f"{prefix}-{counter}"
                seen.add(item["id"])
                counter += 1

    if isinstance(data, dict):
        shared_seen: set[str] = set()
        _process_items(data.get("rules", []), "rule", f"{source_name}.rules", shared_seen)
        for idx, group in enumerate(data.get("groups", []), 1):
            if isinstance(group, dict):
                group_rules = group.get("rules", [])
                _process_items(group_rules, f"group-{idx}-rule", f"{source_name}.groups[{idx}].rules", shared_seen)
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
