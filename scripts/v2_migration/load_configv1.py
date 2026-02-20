import os
import logging
import copy
import yaml
from pydantic import ValidationError, SecretStr
from config_modelv1 import (
    GlobalConfig,
    SwarmServiceConfig,
    ContainerConfig,
)

logger = logging.getLogger(__name__)


class ConfigLoadError(Exception):
    """Raised when config file exists but cannot be loaded or parsed"""
    pass

TOP_LEVEL_KEYS = [
    "notifications", "settings", "global_keywords", "containers", "swarm_services"
    ]


def load_config(path="/config/config.yaml"):
    """
    Load, merge, and validate the application configuration from YAML and environment variables.
    Called from app.py
    Returns: tuple: (validated_config_object, config_file_path_used)
    """
    config_path = None
    yaml_config = None
    error_messages = []
    # Try to load YAML config from available paths
    if os.path.isfile(path):
        config_path = path
        try:
            with open(path, "r") as file:
                yaml_config = yaml.safe_load(file)
        except yaml.YAMLError as e:
            error_messages.append(f"Error parsing YAML file at {path}: {e}")
            logging.error(f"Error parsing YAML file at {path}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error loading {path}: {e}")
            error_messages.append(f"Failed to load {path}: {e}")
    else:
        logging.debug(f"The path {path} does not exist.")
        raise ConfigLoadError(f"The path {path} does not exist.")

    if yaml_config is None:
        if error_messages:
            # Don't load config if there are errors with the config file
            raise ConfigLoadError("\n".join(error_messages))
        logging.warning(f"No config.yaml found in any location")
        yaml_config = {}
    else:
        logging.info(f"The config.yaml file was found in {config_path}.")

    # Ensure required top-level keys exist in yaml_config
    for key in TOP_LEVEL_KEYS:
        if key not in yaml_config or yaml_config[key] is None:
            yaml_config[key] = {}

    yaml_config = convert_legacy_formats(yaml_config)
    # Validate the merged configuration with Pydantic
    config = GlobalConfig.model_validate(yaml_config)
    # yaml_output = get_pretty_yaml_config(config)
    # logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path

def get_pretty_yaml_config(config, top_level_key=None):
    """
    Convert a Pydantic config object to a pretty-printed YAML string.
    
    Args:
        config: Pydantic model instance
        top_level_key: Optional key to wrap the config in
        
    Returns:
        str: Pretty-formatted YAML string
    """
    config_dict = prettify_config_dict(config.model_dump(
        exclude_none=True, 
        exclude_defaults=False, 
        exclude_unset=False,
    ))
    if top_level_key:
        config_dict = {top_level_key: config_dict}
    return yaml.dump(config_dict, default_flow_style=False, sort_keys=False, indent=4)


def prettify_config_dict(data):
    """
    Recursively format config dict for display, masking secrets and ordering keys for readability.
    """
    if isinstance(data, dict):
        # Put regex/keyword keys first for better readability
        priority_keys = [k for k in ("regex", "keyword", "keyword_group", "event") if k in data]
        if priority_keys:
            rest_keys = [k for k in data.keys() if k not in priority_keys]
            ordered_dict = {k: data[k] for k in priority_keys + rest_keys}
            return {k: prettify_config_dict(v) for k, v in ordered_dict.items()}
        return {k: prettify_config_dict(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [prettify_config_dict(item) for item in data]
    elif isinstance(data, SecretStr):
        return "**********"  
    else:
        return data


def convert_legacy_formats(config):
    """
    Migrate legacy configuration fields (e.g., keywords_with_attachment, action_keywords) to the current format.
    """
    def _migrate_keywords(legacy, new, new_field):
        """
        Helper function to migrate legacy keyword lists to new format with additional fields.
        
        Args:
            legacy: List of legacy keyword items
            new: Target list to append converted items to
            new_field: Tuple of (field_name, field_value) to add to each item
        """
        new_key, new_value = new_field
        for item in legacy:
            if isinstance(item, (str, int)):
                new.append({"keyword": str(item), new_key: new_value})
            elif isinstance(item, dict):
                item[new_key] = new_value
                new.append(item)
                
    def _migrate_field_names(config_copy: dict, old: str, new: str, exclude_values: list[str] = []) -> dict:
        keys_to_migrate = []
        for key, value in config_copy.items():
            if key == old and new not in config_copy and value not in exclude_values:
                keys_to_migrate.append(key)
            elif isinstance(value, dict):
                _migrate_field_names(value, old, new, exclude_values)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _migrate_field_names(item, old, new, exclude_values)

        for key in keys_to_migrate:
            config_copy[new] = config_copy.pop(key)
        return config_copy
        
    config_copy = copy.deepcopy(config)
    config_copy = _migrate_field_names(config_copy, "notification_title", "title_template", exclude_values=["default"])
    config_copy = _migrate_field_names(config_copy, "json_template", "message_template")
    config_copy = _migrate_field_names(config_copy, "template", "message_template")
    config_copy = _migrate_field_names(config_copy, "disable_container_event_message", "disable_monitor_event_message")
    
    # Migrate global keywords_with_attachment
    global_kw = config_copy.get("global_keywords", {})
    global_with_attachment = global_kw.pop("keywords_with_attachment", None)
    if global_with_attachment is not None:
        config_copy["global_keywords"].setdefault("keywords", [])
        _migrate_keywords(global_with_attachment, config_copy["global_keywords"]["keywords"], ("attach_logfile", True))
    
    # Migrate container-level legacy fields
    for target_type in ["containers", "swarm_services"]:
        if target_type not in config_copy:
            continue
        for target_config in config_copy.get(target_type, {}).values():
            if target_config is None:
                continue
            target_config.setdefault("keywords", [])

            # Migrate keywords_with_attachment
            keywords_with_attachment = target_config.pop("keywords_with_attachment", None)
            if keywords_with_attachment is not None:
                _migrate_keywords(keywords_with_attachment, target_config["keywords"], ("attach_logfile", True))

            # Migrate action_keywords (legacy action format)
            action_keywords = target_config.pop("action_keywords", None)
            if action_keywords is not None:
                for item in action_keywords:
                    if isinstance(item, dict):
                        if "restart" in item:
                            action = "restart"
                        elif "stop" in item:
                            action = "stop"
                        else:
                            action = None
                        if action:
                            keyword = item[action]
                            if isinstance(keyword, dict) and "regex" in keyword:
                                target_config["keywords"].append({"regex": keyword["regex"], "action": action})
                            elif isinstance(keyword, str):
                                target_config["keywords"].append({"keyword": keyword, "action": action})
    return config_copy


def format_pydantic_error(e: ValidationError) -> str:
    """
    Format Pydantic validation errors for user-friendly display.
    """
    error_messages = []
    for error in e.errors():
        location = ".".join(map(str, error["loc"]))
        msg = error["msg"]
        msg = msg.split("[")[0].strip()  # Remove technical details in brackets
        error_messages.append(f"Field '{location}': {msg}")
    return "\n".join(error_messages)