import os
import logging
import yaml
from pydantic import ValidationError, SecretStr
# from .config_modelv2 import (
#     GlobalConfigV2,
# )

from constants import MonitorType
from config.models.root import GlobalConfigV2
class ConfigLoadError(Exception):
    """Raised when config file exists but cannot be loaded or parsed"""
    pass


def load_configv2(path="/config/config.yaml"):
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

    if yaml_config is None:
        if error_messages:
            # Don't load config if there are errors with the config file
            raise ConfigLoadError("\n".join(error_messages))
        logging.warning(f"No config.yaml found in any location")
        yaml_config = {}
    else:
        logging.info(f"The config.yaml file was found in {config_path}.")

    # Validate the merged configuration with Pydantic
    try:
        config = GlobalConfigV2.model_validate(yaml_config)
    except ValidationError as e:
        logging.error(f"Error validating config: {format_pydantic_error(e)}")
        raise ConfigLoadError(f"Error validating config: {format_pydantic_error(e)}")
    except Exception as e:
        logging.error(f"Unexpected error validating config: {e}")
        raise ConfigLoadError(f"Unexpected error validating config: {e}")
    # config = GlobalConfigV2.model_validate(yaml_config)

    yaml_output = get_pretty_yaml_config(config)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

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