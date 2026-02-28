import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent / "app"))

import argparse
import re
import yaml
import sys
from typing import Any, cast
import copy
import os
from pydantic import ValidationError, SecretStr
from load_configv1 import load_config
from config.models.base import RootDefaultsConfig, SettingsConfig # type: ignore
from config.models.root import GlobalConfig # type: ignore
from config.helpers import prettify_config_dict # type: ignore

class MyDumper(yaml.Dumper):

    # don't use yaml anchors
    # def ignore_aliases(self, data):
    #       return True

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow=flow, indentless=False)

    def write_line_break(self, data=None):
        super().write_line_break(data)
        # add an extra line break after top level keys
        if len(self.indents) == 1:
            super().write_line_break()

    def represent_str(self, data):
        """Use | style for strings that contain newlines or tabs."""
        unescaped = data.replace('\\n', '\n').replace('\\t', '\t')
        if '\n' in unescaped:
            return self.represent_scalar('tag:yaml.org,2002:str', unescaped, style='|')
        return self.represent_scalar('tag:yaml.org,2002:str', data)

MyDumper.add_representer(str, MyDumper.represent_str)


FIELD_RENAMES = {
    "action": "container_action",
    "hide_regex_in_title": "hide_full_regex",
    "excluded_keywords": "ignore_keywords",
    "notification_cooldown": "trigger_cooldown",
    "keyword_group": "all_of",
    "action_cooldown": "container_action_cooldown",
}

DEPRECATED_FIELDS = [
    "monitor_all_containers",
    "monitor_all_swarm_services",
    "excluded_containers",
    "excluded_swarm_services",
    "disable_start_message",
    "disable_shutdown_message",
    "disable_config_reload_message",
    "disable_monitor_event_message",
]

# Maps old disable_* settings fields to their SystemNotifications keys
_SYSTEM_NOTIFICATION_RENAMES = {
    "disable_start_message": "start",
    "disable_shutdown_message": "shutdown",
    "disable_config_reload_message": "config_reload",
    "disable_monitor_event_message": "monitor_event",
}

def _migrate_field_names(config_copy: dict, old: str, new: str, exclude_values: list[str] = [], exclude_keys: list[str] = []) -> dict:
    keys_to_migrate = []
    for key, value in config_copy.items():
        if key in exclude_keys or value in exclude_values:
            continue
        if key == old and new not in config_copy:
            keys_to_migrate.append(key)
        elif isinstance(value, dict):
            _migrate_field_names(value, old, new, exclude_values, exclude_keys)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _migrate_field_names(item, old, new, exclude_values, exclude_keys)

    for key in keys_to_migrate:
        config_copy[new] = config_copy.pop(key)
        _log_message(f"Migrated field '{old}' to '{new}'")
    return config_copy
    

def _extract_defaults(settings: dict) -> dict:
    """Extract modular settings from settings to create defaults section."""
    defaults = {}

    for key in RootDefaultsConfig.model_fields.keys():
        if key in settings:
            defaults[key] = settings.pop(key)
            _log_message(f"Moved '{key}' from settings to defaults")
    return defaults

def _migrate_system_notifications(settings: dict) -> dict | None:
    """Convert disable_* boolean settings to the new system_notifications structure.

    Returns the system_notifications value to use, or None if no migration is needed
    (i.e. all notifications remain at their default enabled state).
    """
    notifications: dict[str, bool] = {}
    for old_key, new_key in _SYSTEM_NOTIFICATION_RENAMES.items():
        if settings.get(old_key) is True:
            notifications[new_key] = False
            _log_message(f"Migrated '{old_key}: true' to 'system_notifications.{new_key}: false'")

    if not notifications:
        return None

    return notifications


def _clean_settings(settings: dict) -> dict:
    """Remove migrated fields, keep only app settings."""
    clean = {}

    for key in SettingsConfig.model_fields.keys():
        if key in settings:
            clean[key] = settings[key]
            _log_message(f"Keeping '{key}' in settings")

    # Migrate disable_* fields to system_notifications
    system_notifications = _migrate_system_notifications(settings)
    if system_notifications is not None:
        clean["system_notifications"] = system_notifications

    # Warn about any unexpected remaining fields
    for key in settings:
        if key not in SettingsConfig.model_fields.keys() \
            and key not in RootDefaultsConfig.model_fields.keys() \
                and key not in DEPRECATED_FIELDS:
            _log_message(f"Unknown setting '{key}' preserved in settings")

    return clean

def _convert_hosts_containers_section(hosts: dict) -> list[dict]:
    """Convert legacy hosts section to rules with scope."""
    rules = []

    for host_name, host_config in hosts.items():
        if host_config is None:
            continue

        host_monitor_all = host_config.get("monitor_all_containers", False)
        host_excluded = host_config.get("excluded_containers", [])
        host_containers = host_config.get("containers", {})

        # Handle host-level monitor_all
        if host_monitor_all:
            r = {
                    "id": f"monitor-all-on-{host_name}",
                    "scope": {"hosts": [host_name]},
                    "match": {
                        "include": {"container_names": ["*"]},
                        },
                }
            if host_excluded:
                r["match"]["exclude"] = {"container_names": host_excluded}
            rules.append(r)
            _log_message(
                f"Converted hosts.{host_name}.monitor_all_containers to scoped rule"
            )

        # Convert host-specific containers
        for container_name, container_config in host_containers.items():
            if container_name in host_excluded:
                _log_message(f"Container '{container_name}' is excluded on host '{host_name}', skipping")
                continue

            if container_config is None:
                container_config = {}

            rule = {
                "id": f"{container_name}-on-{host_name}",
                "container_name": container_name,
                "scope": {"hosts": [host_name]},
            }

            # Copy container config
            for key, value in container_config.items():
                if value is not None and key != "hosts":
                    rule[key] = value

            rules.append(rule)
            _log_message(
                f"Converted hosts.{host_name}.containers.{container_name} to scoped rule"
            )

    return rules


def _convert_swarm(
    old_config: dict,
) -> dict | None:
    """Convert swarm section to v2 rules format."""
    output: dict[str, Any] = {}
    rules: list[dict] = []

    old_swarm = old_config.get("swarm_services", {})
    old_settings = old_config.get("settings", {})
    global_keywords = old_config.get("global_keywords", {})

    monitor_all_swarm = old_settings.get("monitor_all_swarm_services", None)
    excluded_swarm = old_settings.get("excluded_swarm_services", None)


    # Handle never_monitor (from excluded_swarm_services)
    if excluded_swarm:
        output["never_monitor"] = {"service_names": excluded_swarm}
        _log_message(f"Converted excluded_swarm_services to swarm.never_monitor")

    # Handle monitor_all_swarm_services
    if monitor_all_swarm:
        rules.append(
            {
                "id": "monitor-all",
                "service_name": "*",
            }
        )
        _log_message("Converted monitor_all_swarm_services to wildcard rule")

    # Convert global_keywords to source-level keywords
    if global_keywords and global_keywords.get("keywords"):
        output["keywords"] = global_keywords["keywords"]
        _log_message("Moved global_keywords.keywords to swarm.keywords")

    # Convert each container config to a rule
    if old_swarm:
        _log_message(
            "WARNING: Every key under swarm_services will be converted to a rule matching the service name."
            "If you used a 'stack_name' as a key you will need to modify the affected rules manually and replace 'service_name' with 'stack_name'."
            )
        for name, config in old_swarm.items():
            if config is None:
                config = {}
            rule: dict[str, Any] = {}
            rule["service_name"] = name
            rule["id"] = f"{name}"
            # Handle hosts field -> scope
            hosts = config.pop("hosts", None)
            if isinstance(hosts, str):
                hosts = [h.strip() for h in hosts.split(",")]
                rule["scope"] = {"hosts": hosts}
                _log_message(f"Converted hosts field to scope.hosts for '{name}'")
            # Copy remaining config (keywords, container_events, modular settings)
            for key, value in config.items():
                if value is not None and key != "hosts":
                    rule[key] = value
            rules.append(rule)
            _log_message(f"Converted swarm service '{name}' to rule")

    if rules:
        output["rules"] = rules

    # Return None if completely empty
    if not output:
        return None

    return output


def _convert_containers(
    old_config: dict,
) -> dict | None:
    """Convert containers section to v2 rules format."""
    output: dict[str, Any] = {}
    rules: list[dict] = []

    old_containers = old_config.get("containers", {})
    old_settings = old_config.get("settings", {})
    global_keywords = old_config.get("global_keywords", {})

    monitor_all_containers = old_settings.get("monitor_all_containers", None)
    excluded_containers = old_settings.get("excluded_containers", None)

    # Handle never_monitor (from excluded_containers)
    if excluded_containers:
        output["never_monitor"] = {"container_names": excluded_containers}
        _log_message(f"Converted excluded_containers to containers.never_monitor")

    # Handle hosts section
    hosts = old_config.get("hosts", {})
    if hosts:
        host_rules = _convert_hosts_containers_section(hosts)
        rules = host_rules + rules

    # Handle monitor_all_containers
    if monitor_all_containers:
        rules.append(
            {
                "id": "monitor-all",
                "container_name": "*",
            }
        )
        _log_message("Converted monitor_all_containers to wildcard rule")

    # Convert global_keywords to source-level keywords
    if global_keywords and global_keywords.get("keywords"):
        output["keywords"] = global_keywords["keywords"]
        _log_message("Moved global_keywords.keywords to containers.keywords")

    # Convert each container config to a rule
    if old_containers:
        for name, config in old_containers.items():
            if config is None:
                config = {}
            rule: dict[str, Any] = {}
            rule["container_name"] = name
            rule["id"] = f"{name}"
            # Handle hosts field -> scope
            hosts = config.pop("hosts", None)
            if isinstance(hosts, str):
                hosts = [h.strip() for h in hosts.split(",")]
                rule["scope"] = {"hosts": hosts}
                _log_message(f"Converted hosts field to scope.hosts for '{name}'")
            # Copy remaining config (keywords, container_events, modular settings)
            for key, value in config.items():
                if value is not None and key != "hosts":
                    rule[key] = value
            rules.append(rule)
            _log_message(f"Converted container '{name}' to rule")


    if rules:
        output["rules"] = rules

    # Return None if completely empty
    if not output:
        return None

    return output

def _migrate_template_syntax(template: str) -> str:
    """Convert {var} / {dict[key]} Python format_map syntax to Jinja2 {{ var }} syntax."""

    def convert_match(m):
        raw = m.group(1)  # everything inside the outer braces

        # Strip conversion flags (!r, !s, !a) with warning
        bracket_pos_for_flag = raw.find('[')
        root_for_flag = raw if bracket_pos_for_flag == -1 else raw[:bracket_pos_for_flag]
        if '!' in root_for_flag:
            flag_idx = root_for_flag.index('!')
            flag = root_for_flag[flag_idx + 1:flag_idx + 2]
            _log_message(f"WARNING: Conversion flag '!{flag}' in template field '{{{raw}}}' is not supported in Jinja2 and was dropped.")
            raw = root_for_flag[:flag_idx] + (raw[bracket_pos_for_flag:] if bracket_pos_for_flag != -1 else "")

        # Strip format spec (:...) — only on root field (before first [)
        bracket_pos = raw.find('[')
        root = raw if bracket_pos == -1 else raw[:bracket_pos]
        rest = '' if bracket_pos == -1 else raw[bracket_pos:]
        if ':' in root:
            root, _, spec = root.partition(':')
            _log_message(f"WARNING: Format spec ':{spec}' in template field '{{{raw}}}' is not supported in Jinja2 and was dropped.")
        raw = root + rest

        # Convert bracket access to dot/subscript notation
        parts = re.split(r'\[([^\]]+)\]', raw)
        result = parts[0]  # root field name
        for i in range(1, len(parts), 2):
            key = parts[i]
            if key.isdigit():
                result += f'[{key}]'
            elif key.isidentifier():
                result += f'.{key}'
            else:
                result += f"['{key}']"

        return '{{ ' + result + ' }}'

    # Match {field}, {field[key]}, etc. but not {{ or }} (escaped braces)
    return re.sub(r'(?<!\{)\{([a-zA-Z_]\w*(?:\[[^\]]*\])*(?:![rsa])?(?::[^}]*)?)\}(?!\})', convert_match, template)


def _migrate_templates_in_config(config: Any) -> Any:
    """Recursively walk config and migrate title_template / message_template values."""
    if isinstance(config, dict):
        for key, value in config.items():
            if key in ("title_template", "message_template") and isinstance(value, str):
                migrated = _migrate_template_syntax(value)
                if migrated != value:
                    _log_message(f"Migrated template syntax in '{key}': {value!r} -> {migrated!r}")
                config[key] = migrated
            else:
                _migrate_templates_in_config(value)
    elif isinstance(config, list):
        for item in config:
            _migrate_templates_in_config(item)
    return config


def _log_phase(message: str):
    sep = "=" * 100
    _log_message(f"{sep}\n{message}\n{sep}")

def _log_message(message: str):
    print(message, file=sys.stderr)

def _is_v1_config(config: dict) -> bool:
    if config.get("version") == 2:
        _log_message("Config seems to be in v2 format already ('version: 2' found in config), skipping conversion")
        return False
    c = config.get("containers", {})
    sw = config.get("swarm_services", {})
    if config.get("defaults"):
        _log_message("Config seems to be in v2 format already (contains defaults section), skipping conversion")
        return False
    if any(tc.get("rules") for tc in (c, sw)):
        _log_message("Config seems to be in v2 format already (contains rules section), skipping conversion")
        return False
    return True

def _convert_secretstr(config): 
    # recursively convert SecretStr to str
    if isinstance(config, SecretStr):
        return config.get_secret_value()
    elif isinstance(config, dict):
        for key, value in config.items():
            config[key] = _convert_secretstr(value)
        return config
    elif isinstance(config, list):
        return [_convert_secretstr(item) for item in config]
    return config

def convert(path: str = "/config/config.yaml", output_path: str = "/config/configv2.yaml"):

    # detect if config is already v2
    try: 
        with open(path, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        _log_message(f"Error loading config: {e}")
        sys.exit(1)

    if not _is_v1_config(config):
        _log_message("Config does not seem to be in a proper v1 format, skipping conversion")
        return
    
    _log_phase("""
Phase 0: Loading config and validating against v1.8.0 model (this will also perform all legacy migrations up until v1.8.0)
IMPORTANT: If you see warnings during validation they refer to invalid fields in the OLD v1 config. If possible all invalid fields are ignored. Make sure that no important configurations are lost.
""")
    try:
        configv1_8, _ = load_config(path)
    except Exception as e:
        _log_message(f"Error loading/validating v1 config: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    _log_phase("Phase 0.5: Preparing to convert v1 config to v2 config... Migrating field names...")
    # Migrate field names
    configv1_8_dict = configv1_8.model_dump(exclude_none=True)
    renamed_fields_config = copy.deepcopy(configv1_8_dict)
    for key, value in FIELD_RENAMES.items():
        if key == "action" and value == "container_action":
            renamed_fields_config = _migrate_field_names(renamed_fields_config, "action", "container_action", exclude_keys=["notifications", "ntfy_actions"])
            continue
        renamed_fields_config = _migrate_field_names(renamed_fields_config, key, value)
    

    _log_phase("Phase 0.6: Migrating template syntax from {var} to {{ var }} (Jinja2)...")
    renamed_fields_config = _migrate_templates_in_config(renamed_fields_config)

    v1_settings = renamed_fields_config.get("settings", {})
    output: dict[str, Any] = {}

    # Defaults Section
    _log_phase("Phase 1: Extracting defaults from settings...")
    defaults = _extract_defaults(v1_settings)
    if defaults:
        output["defaults"] = defaults

    # Settings Section
    _log_phase("Phase 2: Creating settings section...")
    settings = _clean_settings(v1_settings)
    if settings:
        output["settings"] = settings


    # Convert containers section
    _log_phase("Phase 3: Converting containers section...")
    containers = _convert_containers(renamed_fields_config)
    if containers:
        output["containers"] = containers
    else:
        _log_message("No containers section to convert.")

    # Convert swarm section
    _log_phase("Phase 4: Converting swarm section...")
    swarm = _convert_swarm(renamed_fields_config)
    if swarm:
        output["swarm"] = swarm
    else:
        _log_message("No swarm section to convert.")

    # Copy notifications (unchanged structure)
    _log_phase("Phase 5: Copying notifications section...")
    if renamed_fields_config.get("notifications"):
        output["notifications"] = renamed_fields_config["notifications"]

    # Final Validation
    _log_phase(
"""
Phase 6: Final validation... The new config will now be validated against the v2 model.
While errors during validation are unlikely, if there are any, invalid fields are  mostly ignored. 
If you see any warnings during validation make sure that no important settings are lost
""")

    os.environ["STRICT_CONFIG"] = "false"
    try:
        GlobalConfig.model_validate(copy.deepcopy(output)).model_dump(exclude_none=True)
    except ValidationError as e:
        _log_message(f"Error validating config: {e}")
        _log_message(f"Error details: {e.errors()}")
        _log_message(f"Config: {output}")
        sys.exit(1)
    
    output = cast(dict[str, Any], _convert_secretstr(output))

    preferred_order = [
        "containers",
        "swarm",
        "defaults",
        "notifications",
        "settings",
    ]

    output = {key: output[key] for key in preferred_order if key in output}
    try:
        output = prettify_config_dict(output, mask_secrets=False)
    except Exception as e:
        _log_message(f"Error prettifying config: {e}")
        sys.exit(1)

    yaml_str = yaml.dump(
        output, 
        Dumper=MyDumper, 
        sort_keys=False, 
        indent=2, 
        allow_unicode=True,
        width=300
    )
    with open(output_path, "w") as f:
        f.write(yaml_str)
    return output


def main():
    parser = argparse.ArgumentParser(description="Convert LoggiFly v1 config to v2 format")
    parser.add_argument("-i", "--input", default="/config/config.yaml", help="Input config file path (default: /config/config.yaml)")
    parser.add_argument("-o", "--output", default="/config/configv2.yaml", help="Output file path (default: /config/configv2.yaml)")
    args = parser.parse_args()

    convert(path=args.input, output_path=args.output)

if __name__ == "__main__":
    main()