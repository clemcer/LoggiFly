import os
import logging
import copy
from docker import errors
import yaml
from .config_model import (
    GlobalConfig,
    SwarmServiceConfig,
    ContainerConfig,
    ValidationError,
    SecretStr
)
from constants import MonitorType

logger = logging.getLogger(__name__)


class ConfigLoadError(Exception):
    """Raised when config file exists but cannot be loaded or parsed"""
    pass

TOP_LEVEL_KEYS = [
    "notifications", "settings", "global_keywords", "containers", "swarm_services"
    ]

"""
This module handles configuration loading and validation using Pydantic models. 
YAML configuration is loaded first, then environment variables are merged in, allowing 
environment variables to override YAML values, and YAML to override defaults. 
The merged configuration is validated with Pydantic. Legacy config formats are migrated for compatibility.
"""

def merge_yaml_and_env(yaml, env_update):
    """
    Merge environment variables and YAML configuration.
    """
    def merge_dict_with_precedence(y, e):
        for k, v in e.items():
            if v is not None:
                y[k] = v
        return y

    for key, value in env_update.items():
        if not isinstance(value, dict):
            continue
        if not yaml.get(key):
            yaml[key] = {}
        if isinstance(value, dict) and key in ("containers", "swarm_services"):
            yaml[key] = merge_dict_with_precedence(yaml[key], value)
        elif key == "global_keywords":
            yaml[key] = merge_dict_with_precedence(yaml[key], value)
        elif key == "notifications":
            for notification_type, notification_value in value.items(): # ntfy, apprise, webhook
                if notification_value:
                    if not yaml[key].get(notification_type): 
                        yaml[key][notification_type] = {}
                    yaml[key][notification_type] = merge_dict_with_precedence(yaml[key][notification_type], notification_value)
        elif key == "settings":
            yaml[key] = merge_dict_with_precedence(yaml[key], value)
    return yaml


def convert_string_to_list(string: str | None) -> list:
    return [s.strip() for s in string.split(",") if s.strip()] if string else []


def load_env_config(yaml_exists: bool):

    ENV_SETTINGS = {
        "log_level": os.getenv("LOG_LEVEL"),
        "multi_line_entries": os.getenv("MULTI_LINE_ENTRIES"),
        "reload_config": False if not yaml_exists else os.getenv("RELOAD_CONFIG"), 
        "disable_start_message": os.getenv("DISABLE_START_MESSAGE"),
        "disable_restart_message": os.getenv("DISABLE_RESTART_MESSAGE"),
        "disable_config_reload_message": os.getenv("DISABLE_CONFIG_RELOAD_MESSAGE"),
        "disable_shutdown_message": os.getenv("DISABLE_SHUTDOWN_MESSAGE"),
        "disable_monitor_event_message": os.getenv("DISABLE_MONITOR_EVENT_MESSAGE"), # previously: disable_container_event_message
        "compact_summary_message": os.getenv("COMPACT_SUMMARY_MESSAGE"),
        
        "monitor_all_containers": os.getenv("MONITOR_ALL_CONTAINERS"),
        "monitor_all_swarm_services": os.getenv("MONITOR_ALL_SWARM_SERVICES"),
        "excluded_containers": convert_string_to_list(os.getenv("EXCLUDED_CONTAINERS")) or None,
        "excluded_swarm_services": convert_string_to_list(os.getenv("EXCLUDED_SWARM_SERVICES")) or None,

        # legacy settings (converted to new settings in load_config)
        "notification_title": os.getenv("NOTIFICATION_TITLE"),
        "disable_container_event_message": os.getenv("DISABLE_CONTAINER_EVENT_MESSAGE"),

        # modular settings
        "attach_logfile": os.getenv("ATTACH_LOGFILE"),
        "notification_cooldown": os.getenv("NOTIFICATION_COOLDOWN"),
        "title_template": os.getenv("TITLE_TEMPLATE"), # previously: notification_title
        "message_template": os.getenv("MESSAGE_TEMPLATE"), # previously: json_template and template
        "action_cooldown": os.getenv("ACTION_COOLDOWN"),
        "attachment_lines": os.getenv("ATTACHMENT_LINES"),
        "hide_regex_in_title": os.getenv("HIDE_REGEX_IN_TITLE"),
        "excluded_keywords": convert_string_to_list(os.getenv("EXCLUDED_KEYWORDS")) or None,
        "disable_notifications": os.getenv("DISABLE_NOTIFICATIONS"),
        "olivetin_url": os.getenv("OLIVETIN_URL"),
        "olivetin_username": os.getenv("OLIVETIN_USERNAME"),
        "olivetin_password": os.getenv("OLIVETIN_PASSWORD"),
    } 
    
    # Ntfy notification settings
    ENV_NTFY =  {
        "url": os.getenv("NTFY_URL"),
        "topic": os.getenv("NTFY_TOPIC"),
        "token": os.getenv("NTFY_TOKEN"),
        "priority": os.getenv("NTFY_PRIORITY"),
        "tags": os.getenv("NTFY_TAGS"),
        "username": os.getenv("NTFY_USERNAME"),
        "password": os.getenv("NTFY_PASSWORD"),
        "icon": os.getenv("NTFY_ICON"),
        "click": os.getenv("NTFY_CLICK"),
        "markdown": os.getenv("NTFY_MARKDOWN"),
        # actions and headers are currently not supported since they come in dicts
    }
    
    # Webhook settings
    ENV_WEBHOOK = {"url": os.getenv("WEBHOOK_URL")}
    
    # Apprise settings
    ENV_APPRISE = {"url": os.getenv("APPRISE_URL")}
    
    # Global keywords from environment
    ENV_GLOBAL_KEYWORDS = {
        "keywords": convert_string_to_list(os.getenv("GLOBAL_KEYWORDS")) or None,
        "keywords_with_attachment": convert_string_to_list(os.getenv("GLOBAL_KEYWORDS_WITH_ATTACHMENT")) or None,
    }
    ENV_CONTAINERS = convert_string_to_list(os.getenv("CONTAINERS"))
    ENV_SWARM_SERVICES = convert_string_to_list(os.getenv("SWARM_SERVICES"))
    
    # Fill env_config dict with environment variables if they are set
    env_config = {
        "notifications": {}, 
        "settings": {}, 
        "global_keywords": {},
        "containers": {},
        "swarm_services": {},
    }
    for container in ENV_CONTAINERS:
        env_config["containers"][container] = {}
    for swarm_service in ENV_SWARM_SERVICES:
        env_config["swarm_services"][swarm_service] = {}

    if any(ENV_NTFY.values()):
        env_config["notifications"]["ntfy"] = ENV_NTFY

    if ENV_APPRISE["url"]: 
        env_config["notifications"]["apprise"] = ENV_APPRISE

    if ENV_WEBHOOK["url"]:
        env_config["notifications"]["webhook"] = ENV_WEBHOOK

    for k, v in ENV_GLOBAL_KEYWORDS.items():
        if v:
            env_config["global_keywords"][k]= v

    # Add settings if set
    for key, value in ENV_SETTINGS.items(): 
        if value is not None:
            env_config["settings"][key] = value

    return env_config


def load_config(official_path="/config/config.yaml"):
    """
    Load, merge, and validate the application configuration from YAML and environment variables.
    Called from app.py
    Returns: tuple: (validated_config_object, config_file_path_used)
    """
    config_path = None
    yaml_config = None
    legacy_path = "/app/config.yaml"
    paths = [official_path, legacy_path]
    error_messages = []
    # Try to load YAML config from available paths
    for path in paths:
        logging.debug(f"Trying path: {path}")
        if os.path.isfile(path):
            config_path = path
            try:
                with open(path, "r") as file:
                    yaml_config = yaml.safe_load(file)
                    break
            except yaml.YAMLError as e:
                error_messages.append(f"Error parsing YAML file at {path}: {e}")
                logging.error(f"Error parsing YAML file at {path}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error loading {path}: {e}")
                error_messages.append(f"Failed to load {path}: {e}")
        else:
            logging.debug(f"The path {path} does not exist.")

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

    env_config = load_env_config(yaml_exists=yaml_config is not None)
    # Merge environment variables and yaml config
    merged_config = merge_yaml_and_env(yaml_config, env_config)
    merged_config = convert_legacy_formats(merged_config)
    # Validate the merged configuration with Pydantic
    config = GlobalConfig.model_validate(merged_config)
    yaml_output = get_pretty_yaml_config(config)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path

def validate_unit_config(monitor_type, config_dict):
    """
    Validate a container or swarm service configuration using the appropriate Pydantic model.
    
    Args:
        monitor_type: MonitorType.CONTAINER or MonitorType.SWARM
        config_dict: Configuration dictionary to validate
        
    Returns:
        Validated config object or None if validation fails
    """
    try:
        if monitor_type == MonitorType.SWARM:
            return SwarmServiceConfig.model_validate(config_dict)
        elif monitor_type == MonitorType.CONTAINER:
            return ContainerConfig.model_validate(config_dict)
    except ValidationError as e:
        type_str = monitor_type.value if hasattr(monitor_type, "value") else monitor_type
        logging.error(f"Error validating {type_str} config: {format_pydantic_error(e)}")
        return None
    except Exception as e:
        type_str = monitor_type.value if hasattr(monitor_type, "value") else monitor_type
        logging.error(f"Unexpected error validating {type_str} config: {e}")
        return None


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
            logger.debug(f"Migrating field {key} to {new}")
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
    for unit_type in ["containers", "swarm_services"]:
        if unit_type not in config_copy:
            continue
        for unit_config in config_copy.get(unit_type, {}).values():
            if unit_config is None:
                continue
            unit_config.setdefault("keywords", [])
            
            # Migrate keywords_with_attachment
            keywords_with_attachment = unit_config.pop("keywords_with_attachment", None)
            if keywords_with_attachment is not None:
                _migrate_keywords(keywords_with_attachment, unit_config["keywords"], ("attach_logfile", True))
            
            # Migrate action_keywords (legacy action format)
            action_keywords = unit_config.pop("action_keywords", None)
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
                                unit_config["keywords"].append({"regex": keyword["regex"], "action": action})
                            elif isinstance(keyword, str):
                                unit_config["keywords"].append({"keyword": keyword, "action": action})
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