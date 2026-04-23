import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent / "app"))

import argparse
import re
import yaml
import sys
from io import StringIO
from typing import Any, cast
import copy
import os
from pydantic import ValidationError, SecretStr
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
from load_configv1 import load_config
from config.models.base import RootDefaultsConfig, SettingsConfig # type: ignore
from config.models.root import RootConfig # type: ignore
from config.models.docker import ContainerRule, SwarmRule # type: ignore
from config.helpers import prettify_config_dict # type: ignore


def _prepare_for_ruamel(data: Any) -> Any:
    """Recursively convert multiline strings to LiteralScalarString for | block style.
    Also unescapes literal \\n sequences to real newlines."""
    if isinstance(data, dict):
        return {k: _prepare_for_ruamel(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_prepare_for_ruamel(item) for item in data]
    elif isinstance(data, str):
        unescaped = data.replace('\\n', '\n').replace('\\t', '\t')
        if '\n' in unescaped:
            return LiteralScalarString(unescaped)
        return data
    return data


TEMPLATE_VAR_RENAMES = {
    "action_result_message": "container_action_result_message",
    "action_type": "container_action_type",
    "action_string": "container_action_string",
    "action_target": "container_action_target",
    "action_succeeded": "container_action_succeeded",
}

FIELD_RENAMES = {
    "action": "container_action",
    "hide_regex_in_title": "hide_full_regex",
    "excluded_keywords": "ignore_keywords",
    "notification_cooldown": "trigger_cooldown",
    "keyword_group": "all_of",
    "action_cooldown": "container_action_cooldown",
    "disable_notifications": "disable_trigger_notifications",
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
    """Convert legacy hosts section to one group per host."""
    groups = []

    for host_name, host_config in hosts.items():
        if host_config is None:
            continue

        host_monitor_all = host_config.get("monitor_all_containers", False)
        host_excluded = host_config.get("excluded_containers", [])
        host_containers = host_config.get("containers", {})

        group: dict[str, Any] = {
            "scope": {"hosts": [host_name]},
            "rules": [],
        }

        if host_excluded:
            group["never_monitor"] = {"container_names": host_excluded}
            _log_message(f"Converted hosts.{host_name}.excluded_containers to group never_monitor")

        if host_monitor_all:
            group["rules"].append({
                "id": f"monitor-all-on-{host_name}",
                "match": {"include": {"container_names": ["*"]}},
            })
            _log_message(f"Converted hosts.{host_name}.monitor_all_containers to wildcard rule in group")

        for container_name, container_config in host_containers.items():
            if container_config is None:
                container_config = {}

            rule: dict[str, Any] = {
                "id": f"{container_name}-on-{host_name}",
                "container_name": container_name,
            }
            for key, value in container_config.items():
                if value is not None and key in ContainerRule.model_fields:
                    rule[key] = value
                elif value is not None:
                    _log_message(f"WARNING: Unknown field '{key}' in hosts.{host_name}.containers.{container_name}, skipping")

            group["rules"].append(rule)
            _log_message(f"Converted hosts.{host_name}.containers.{container_name} to rule in group")

        if group["rules"]:
            groups.append(group)
        else:
            _log_message(f"Skipping empty group for host '{host_name}' (no rules generated)")

    return groups


def _convert_swarm(
    old_config: dict,
) -> dict | None:
    """Convert swarm section to v2 rules format."""
    output: dict[str, Any] = {}
    rules: list[dict] = []

    old_swarm = old_config.get("swarm_services", {})
    old_settings = old_config.get("settings", {})

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
                if value is not None and key in SwarmRule.model_fields:
                    rule[key] = value
                elif value is not None:
                    _log_message(f"WARNING: Unknown field '{key}' in swarm_services.{name}, skipping")
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

    monitor_all_containers = old_settings.get("monitor_all_containers", None)
    excluded_containers = old_settings.get("excluded_containers", None)

    # Handle never_monitor (from excluded_containers)
    if excluded_containers:
        output["never_monitor"] = {"container_names": excluded_containers}
        _log_message(f"Converted excluded_containers to containers.never_monitor")

    # Handle hosts section
    hosts = old_config.get("hosts", {})
    if hosts:
        host_groups = _convert_hosts_containers_section(hosts)
        if host_groups:
            output["groups"] = host_groups

    # Handle monitor_all_containers
    if monitor_all_containers:
        rules.append(
            {
                "id": "monitor-all",
                "container_name": "*",
            }
        )
        _log_message("Converted monitor_all_containers to wildcard rule")


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
                if value is not None and key in ContainerRule.model_fields:
                    rule[key] = value
                elif value is not None:
                    _log_message(f"WARNING: Unknown field '{key}' in containers.{name}, skipping")
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


def _rename_template_vars(template: str) -> str:
    """Rename action_* template variables to container_action_* in a Jinja2 template string."""
    for old, new in TEMPLATE_VAR_RENAMES.items():
        # Match {{ old_var }} with optional whitespace, as a whole word (not a substring)
        pattern = r'(\{\{[\s]*)' + re.escape(old) + r'([\s]*\}\})'
        replacement = r'\g<1>' + new + r'\2'
        template, count = re.subn(pattern, replacement, template)
        if count:
            _log_message(f"Renamed template variable '{old}' to '{new}'")
    return template


def _migrate_templates_in_config(config: Any) -> Any:
    """Recursively walk config and migrate title_template / message_template values."""
    if isinstance(config, dict):
        for key, value in config.items():
            if key in ("title_template", "message_template") and isinstance(value, str):
                migrated = _migrate_template_syntax(value)
                migrated = _rename_template_vars(migrated)
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

    input_path = Path(path)
    if not input_path.exists():
        _log_message(
            f"Error: Input file not found: '{path}'\n"
            f"  Make sure you mounted the correct directory. Example:\n"
            f"    docker run --rm -v /path/to/your/config:/config ghcr.io/clemcer/loggifly-migrate:v1-to-v2"
        )
        sys.exit(1)
    if not input_path.is_file():
        _log_message(
            f"Error: '{path}' is not a readable file (found a directory at that path).\n"
            f"  This can happen when Docker creates the mount target as a directory\n"
            f"  because the source path does not exist on the host or is itself a directory.\n"
            f"  Mount the parent directory of your config.yaml instead:\n"
            f"    docker run --rm -v /path/to/your/config:/config ghcr.io/clemcer/loggifly-migrate:v1-to-v2"
        )
        sys.exit(1)

    output_dir = Path(output_path).parent
    if not output_dir.exists():
        _log_message(
            f"Error: Output directory does not exist: '{output_dir}'\n"
            f"  Make sure the output path is within a mounted volume."
        )
        sys.exit(1)

    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        _log_message(f"Error: Failed to parse YAML in '{path}':\n  {e}")
        sys.exit(1)
    except PermissionError:
        _log_message(f"Error: Permission denied reading '{path}'.")
        sys.exit(1)
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
    configv1_8_dict = configv1_8.model_dump(exclude_none=True, exclude_unset=True)
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

    # Global Section (defaults + global_keywords)
    _log_phase("Phase 1: Extracting defaults and global keywords into global section...")
    global_section: dict[str, Any] = {}
    defaults = _extract_defaults(v1_settings)
    if defaults:
        global_section["defaults"] = defaults
    global_keywords = renamed_fields_config.get("global_keywords", {})
    if global_keywords and global_keywords.get("keywords"):
        global_section["keywords"] = global_keywords["keywords"]
        _log_message("Moved global_keywords.keywords to global.keywords")
    if global_section:
        output["global"] = global_section

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
Phase 6: Validating migrated config against the v2 schema...
Validation errors are unlikely, but if there are any, invalid fields will be dropped. 
Review any warnings below to confirm no important settings were lost.
""")

    os.environ["STRICT_CONFIG"] = "false"
    try:
        RootConfig.model_validate(copy.deepcopy(output)).model_dump(exclude_none=True)
    except ValidationError as e:
        _log_message(f"Error validating config: {e}")
        _log_message(f"Error details: {e.errors()}")
        _log_message(f"Config: {output}")
        sys.exit(1)
    
    output = cast(dict[str, Any], _convert_secretstr(output))

    preferred_order = [
        "global",
        "containers",
        "swarm",
        "notifications",
        "settings",
    ]

    output = {key: output[key] for key in preferred_order if key in output}
    try:
        output = prettify_config_dict(output, mask_secrets=False)
    except Exception as e:
        _log_message(f"Error prettifying config: {e}")
        sys.exit(1)

    output = _prepare_for_ruamel(output)

    ryaml = YAML()
    ryaml.default_flow_style = False
    ryaml.allow_unicode = True
    ryaml.width = 4096
    ryaml.indent(mapping=2, sequence=4, offset=2)

    stream = StringIO()
    ryaml.dump(output, stream)
    yaml_str = stream.getvalue()

    yaml_str = re.sub(r'\n([a-zA-Z_])', r'\n\n\1', yaml_str)

    try:
        with open(output_path, "w") as f:
            f.write(yaml_str)
    except PermissionError:
        _log_message(f"Error: Permission denied writing to '{output_path}'. Check volume mount permissions.")
        sys.exit(1)
    except Exception as e:
        _log_message(f"Error writing output file: {e}")
        sys.exit(1)
    _log_message(f"\nMigration complete. Output written to: {output_path}")
    return output


def main():
    parser = argparse.ArgumentParser(description="Convert LoggiFly v1 config to v2 format")
    parser.add_argument("-i", "--input", default="/config/config.yaml", help="Input config file path (default: /config/config.yaml)")
    parser.add_argument("-o", "--output", default="/config/configv2.yaml", help="Output file path (default: /config/configv2.yaml)")
    args = parser.parse_args()

    convert(path=args.input, output_path=args.output)

if __name__ == "__main__":
    main()