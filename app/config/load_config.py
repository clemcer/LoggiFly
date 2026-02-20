import os
import logging
import yaml
from typing import Any
from constants import NotificationPrefix
from config.models.root import GlobalConfig
from config.models.base import SettingsConfig, RootDefaultsConfig, NotificationDefaults
from config.helpers import stringify_numbers, get_pretty_yaml_config
from utils import get_env_var

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


    skip_keys = ["NTFY_ACTIONS", "NTFY_HEADERS", "WEBHOOK_HEADERS"]
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

    cnf.setdefault("settings", {})
    cnf["settings"].update(get_env_config(setting_keys, skip_keys, list_keys))
    cnf.setdefault("defaults", {})
    cnf["defaults"].update(get_env_config(defaults_keys, skip_keys + notification_defaults_keys, list_keys))

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

    # CONTAINERS 
    containers_keywords = get_list_or_none(get_env_var("CONTAINERS_KEYWORDS"))
    containers_container_events = get_list_or_none(get_env_var("CONTAINERS_CONTAINER_EVENTS"))
    containers_scope_hosts = get_list_or_none(get_env_var("CONTAINERS_SCOPE_HOSTS"))
    containers_never_monitor = get_list_or_none(get_env_var("CONTAINERS_EXCLUDE"))
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

    # SWARM SERVICES
    swarm_keywords = get_list_or_none(get_env_var("SWARM_KEYWORDS"))
    swarm_container_events = get_list_or_none(get_env_var("SWARM_CONTAINER_EVENTS"))
    swarm_scope_hosts = get_list_or_none(get_env_var("SWARM_SCOPE_HOSTS"))
    services_never_monitor = get_list_or_none(get_env_var("SWARM_SERVICES_EXCLUDE"))
    stacks_never_monitor = get_list_or_none(get_env_var("SWARM_STACKS_EXCLUDE"))

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
            cnf.setdefault("swarm", {}).setdefault("rules", [])
            cnf["swarm"]["rules"].insert(idx, {
                "id": f"environment-rule-{idx+1}",
                "match": {"include": {key: value}},
            })
    return cnf


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
    config = GlobalConfig.model_validate(yaml_config)

    yaml_output = get_pretty_yaml_config(config)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path


