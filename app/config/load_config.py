import os
import logging
import yaml
from typing import Any
from pydantic import ValidationError
from constants import NotificationPrefix
from config.models.root import RootConfig
from config.models.base import SettingsConfig, RootDefaultsConfig, NotificationDefaults, SystemNotifications
from config.helpers import stringify_numbers, get_pretty_yaml_config, format_pydantic_error
from utils import get_env_var, is_true_env_var

CONFIG_PATH = get_env_var("CONFIG_PATH", fallback_value="/config/config.yaml") or "/config/config.yaml"


class ConfigLoadError(Exception):
    """Raised when config file exists but cannot be loaded or parsed"""
    pass

def override_with_env(cnf: dict) -> dict:

    def get_list_or_none(value):
        return [x.strip() for x in value.split(",")] if value is not None else None

    def get_env_config(keys, skip_keys, list_keys):
        env_config = {}
        for key in keys:
            if key in skip_keys:
                continue
            value = get_env_var(key)
            if value is None:
                continue
            if key in list_keys:
                env_config[key.lower()] = get_list_or_none(value)
            else:
                env_config[key.lower()] = value
        return env_config

    def set_nested_field(cnf: dict, path: tuple, value: Any):
        if not value:
            return
        current = cnf
        for key in path[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[path[-1]] = value


    skip_keys = ["NTFY_ACTIONS", "NTFY_HEADERS", "WEBHOOK_HEADERS", "SYSTEM_NOTIFICATIONS"]
    list_keys = ["IGNORE_KEYWORDS"]

    notification_defaults_keys = [
        k.upper() for k in NotificationDefaults.model_fields.keys() if k.upper() not in skip_keys
        ]
    setting_keys = [
        k.upper() for k in SettingsConfig.model_fields.keys() if k.upper() not in skip_keys
        ]
    defaults_keys = [
        k.upper() for k in RootDefaultsConfig.model_fields.keys() if k.upper() not in skip_keys + notification_defaults_keys
        ] # Notification settings are set under notifications not defaults

    global_keywords = get_list_or_none(get_env_var("GLOBAL_KEYWORDS"))
    
    system_notification_keys = {}
    for key in (SystemNotifications.model_fields.keys()):
        env_value = get_env_var(f"SYSTEM_NOTIFICATIONS_{key.upper()}")
        if env_value:
            system_notification_keys[key] = is_true_env_var(env_value)
    
    system_notifications = get_env_var("SYSTEM_NOTIFICATIONS")

    # SETTINGS BLOCK ------------------------------------------------------------
    cnf.setdefault("settings", {})

    if system_notifications is not None:
        cnf["settings"]["system_notifications"] = is_true_env_var(system_notifications)
    elif system_notification_keys:
        cnf["settings"].setdefault("system_notifications", {})
        cnf["settings"]["system_notifications"].update(system_notification_keys)

    cnf["settings"].update(get_env_config(setting_keys, skip_keys, list_keys))

    # GLOBAL BLOCK ----------------------------------------------------------------
    cnf.setdefault("global", {})
    cnf["global"].setdefault("defaults", {})
    cnf["global"]["defaults"].update(get_env_config(
        keys=defaults_keys, 
        skip_keys=skip_keys + notification_defaults_keys, 
        list_keys=list_keys
        ))
    if global_keywords:
        cnf["global"].setdefault("keywords", [])
        cnf["global"]["keywords"].extend(global_keywords)

    # NOTIFICATIONS BLOCK ------------------------------------------------------------
    for key in notification_defaults_keys:
        # under defaults they have a prefix, under notifications they don't
        env = get_env_var(key)
        if env is None or key in skip_keys:
            continue
        cnf.setdefault("notifications", {})
        key = key.lower()
        prefix = next((p for p in [nt.value for nt in NotificationPrefix] if key.startswith(p)), None)
        if prefix:
            notification_type = prefix.rstrip("_").lower() # NTFY_ -> ntfy
            setting_key = key.replace(prefix, "").lower() # NTFY_URL -> url
            cnf["notifications"].setdefault(notification_type, {})
            cnf["notifications"][notification_type][setting_key] = env

    # CONTAINERS BLOCK ------------------------------------------------------------
    containers_keywords = get_list_or_none(get_env_var("CONTAINERS_KEYWORDS"))
    containers_container_events = get_list_or_none(get_env_var("CONTAINERS_CONTAINER_EVENTS"))
    containers_scope_hosts = get_list_or_none(get_env_var("CONTAINERS_SCOPE_HOSTS"))
    containers_never_monitor = get_list_or_none(get_env_var("CONTAINERS_NEVER_MONITOR"))
    set_nested_field(cnf, ("containers", "keywords"), containers_keywords)
    set_nested_field(cnf, ("containers", "container_events"), containers_container_events)
    set_nested_field(cnf, ("containers", "scope", "hosts"), containers_scope_hosts)
    set_nested_field(cnf, ("containers", "never_monitor", "container_names"), containers_never_monitor)

    containers_list = get_list_or_none(get_env_var("CONTAINERS"))
    if containers_list:
        cnf.setdefault("containers", {}).setdefault("rules", [])
        cnf["containers"]["rules"].insert(0,
            {
                "id": "environment-rule",
                "match": {"include": {"container_names": containers_list}},
            }
        )

    # SWARM SERVICES BLOCK ------------------------------------------------------------
    swarm_keywords = get_list_or_none(get_env_var("SWARM_KEYWORDS"))
    swarm_container_events = get_list_or_none(get_env_var("SWARM_CONTAINER_EVENTS"))
    swarm_scope_hosts = get_list_or_none(get_env_var("SWARM_SCOPE_HOSTS"))
    services_never_monitor = get_list_or_none(get_env_var("SWARM_SERVICES_NEVER_MONITOR"))
    stacks_never_monitor = get_list_or_none(get_env_var("SWARM_STACKS_NEVER_MONITOR"))

    set_nested_field(cnf, ("swarm", "keywords"), swarm_keywords)
    set_nested_field(cnf, ("swarm", "container_events"), swarm_container_events)
    set_nested_field(cnf, ("swarm", "scope", "hosts"), swarm_scope_hosts)
    set_nested_field(cnf, ("swarm", "never_monitor", "service_names"), services_never_monitor)
    set_nested_field(cnf, ("swarm", "never_monitor", "stack_names"), stacks_never_monitor)

    swarm_services_list = get_list_or_none(get_env_var("SWARM_SERVICES"))
    swarm_stacks_list = get_list_or_none(get_env_var("SWARM_STACKS"))
    for idx, kv in enumerate([("service_names", swarm_services_list), ("stack_names", swarm_stacks_list)]):
        key, value = kv
        if value:
            cnf.setdefault("swarm", {}).setdefault("rulesm", [])
            cnf["swarm"]["rules"].insert(idx, {
                "id": f"environment-rule-{idx+1}",
                "match": {"include": {key: value}},
            })
    return cnf


def is_v1_config(config: dict) -> bool:
    if config.get("version") == 2:
        return False
    c = config.get("containers", {})
    if isinstance(c, dict) and isinstance(c.get("rules"), list):
        return False
    if config.get("global", {}).get("defaults"):
        return False

    if config.get("global_keywords"):
        return True
    if config.get("swarm_services") and not config.get("swarm"):
        return True
    v2_container_keys = {"rules", "groups", "never_monitor", "scope", "keywords", "container_events"}
    if isinstance(c, dict) and c and not (c.keys() & v2_container_keys):
        return True
    return False


def load_config(path: str = CONFIG_PATH):
    config_path = None
    yaml_config = None
    error_messages = []
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

    if yaml_config is None:
        if error_messages:
            # Don't load config if there are errors with the config file
            raise ConfigLoadError("\n".join(error_messages))
        logging.warning(f"No config.yaml found in any location")
        yaml_config = {}
    else:
        logging.info(f"The config.yaml file was found in {config_path}.")
   
    # Recursively convert ints/floats to strings in a config dict.                                                                                                
    # Pydantic coerces strings back to int/float where needed, but won't coerce int to str. 
    yaml_config = stringify_numbers(yaml_config)
    
    yaml_config = override_with_env(cnf=yaml_config)
    try:
        config = RootConfig.model_validate(yaml_config)
    except ValidationError as e:
        is_v1 = is_v1_config(yaml_config)      
        logging.debug(e)
        if is_v1:
            error_message = (
                f"\n{'-' * 100}\n"
                "CONFIG VALIDATION ERROR: CONFIG SEEMS TO BE IN V1 FORMAT\n"
                "Please check out https://clemcer.github.io/LoggiFly/guide/migrate-to-v2 to migrate to v2\n"
                f"\n{'-' * 100}\n"
                f"Error: {format_pydantic_error(e)}"
                f"\n{'-' * 100}\n"
                "CONFIG VALIDATION ERROR: CONFIG SEEMS TO BE IN V1 FORMAT\n"
                "Please check out https://clemcer.github.io/LoggiFly/guide/migrate-to-v2 to migrate to v2\n"
                f"\n{'-' * 100}\n"
            )
        else:
            error_message = (
                f"Config validation failed: {format_pydantic_error(e)} (Enable Debug Logging (via env) to see full pydantic error)\n"
                "You can also set the environment variable STRICT_CONFIG to false to ignore (most) validation errors and only log warnings instead. "
                "However this means that the parts of the config causing the error might get ignored and not applied.  You should always double check for any warnings if you decide to do this."
                )

        raise ConfigLoadError(error_message)
    except Exception as e:
        raise ConfigLoadError(f"Unexpected error loading config: {e}")

    yaml_output = get_pretty_yaml_config(config)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path


