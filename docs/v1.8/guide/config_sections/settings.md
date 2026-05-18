---
title: Settings Section
---

# Settings

These are all the possible global settings you can set in the config.yaml.<br>
Configuring these settings is optional since they all have default values.<br>

::: details Click to see full YAML configuration example
```yaml
settings:
  # Logging & Application Behavior
  log_level: INFO
  multi_line_entries: true
  reload_config: true

  # System notifications
  disable_start_message: false
  disable_shutdown_message: false
  disable_config_reload_message: false
  disable_monitor_event_message: false
  compact_summary_message: false

  # Monitor all containers / swarm services
  monitor_all_containers: false
  monitor_all_swarm_services: false
  excluded_containers:
    - container1
    - container2
  excluded_swarm_services:
    - service1
    - stack1

  # Modular settings (can also be configured per container or per trigger)
  notification_cooldown: 5
  action_cooldown: 300
  disable_notifications: false
  attach_logfile: false
  attachment_lines: 20
  hide_regex_in_title: false
  regex_case_sensitive: false
  title_template: "{container}: {keywords}"
  message_template: "Custom message template"
  excluded_keywords:
    - keyword1
    - regex: pattern.*

  # OliveTin Integration
  olivetin_url: http://olivetin:1337
  olivetin_username: admin
  olivetin_password: secret
```
:::


## System-wide Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `log_level` | `INFO` | Logging level for the application (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `multi_line_entries` | `true` | Catch log entries that span multiple lines instead of going line by line |
| `reload_config` | `true` | Automatically reload config.yaml file when changes are detected |
| `disable_start_message` | `false` | Suppress startup notification |
| `disable_shutdown_message` | `false` | Suppress shutdown notification |
| `disable_config_reload_message` | `false` | Suppress config reload notification |
| `disable_monitor_event_message` | `false` | Suppress notification when monitoring of a container starts/stops |
| `compact_summary_message` | `false` | Format summary as comma-separated list instead of multi-line in startup and config reload notifications |
| `monitor_all_containers` | `false` | Monitor all containers (see [section](#monitor-all-containers-swarm-services) below) |
| `monitor_all_swarm_services` | `false` | Monitor all swarm services (see [section](#monitor-all-containers-swarm-services) below) |
| `excluded_containers` | - | List of container names that should not be monitored (use with `monitor_all_containers`) |
| `excluded_swarm_services` | - | List of swarm service names that should not be monitored (use with `monitor_all_swarm_services`) |

## Modular Settings
These settings can also be configured per container or per trigger (see [`containers` section](./containers.md#settings-per-container-and-keyword) for more information).


| Setting | Default | Description |
|---------|---------|-------------|
| `notification_cooldown` | `5` | Seconds between repeated alerts for the same keyword per container |
| `action_cooldown` | `300` | Cooldown in seconds before next container action can be triggered (min: 10s) |
| `disable_notifications` | `false` | Suppress notifications from log events (useful for action-only workflows) |
| `attach_logfile` | `false` | Attach log file to notifications |
| `attachment_lines` | `20` | Number of log lines to include in attachments |
| `hide_regex_in_title` | `false` | Don't show full regex pattern in found keywords in notification titles for cleaner look. Useful when using very long regexes.|
| `regex_case_sensitive` | `false` | Case sensitive regex matching |
| `excluded_keywords` | - | List of keywords that will always be ignored in log lines (see [section](#excluded-keywords) below) |
| `title_template` | - | Custom template for notification titles. ([Customize Notifications](../customize-notifications/)) |
| `message_template` | - | Custom template for notification messages. ([Customize Notifications](../customize-notifications/)) |
| `olivetin_url` | - | URL of your OliveTin instance ([OliveTin Actions](../actions.md#trigger-olivetin-actions)) |
| `olivetin_username` | - | Username for OliveTin authentication ([OliveTin Actions](../actions.md#trigger-olivetin-actions)) |
| `olivetin_password` | - | Password for OliveTin authentication ([OliveTin Actions](../actions.md#trigger-olivetin-actions)) |

---


## Excluded Keywords

With this setting you can specify keywords that should _always_ be ignored. This is useful when you don't want to get notifications from irrelevant log lines.

`excluded_keywords` are set like this:

```yaml
settings:
  excluded_keywords:
    - keyword1
    - regex: regex-pattern1
    - keyword: keyword2
```

## Monitor All Containers / Swarm Services

With the `monitor_all_containers` and `monitor_all_swarm_services` settings you can monitor all containers or swarm services. 
If you want to exclude certain containers or swarm services from monitoring, you can use the `excluded_containers` and `excluded_swarm_services` settings.<br>
Note that you can exclude swarm services by their service name or stack name.

```yaml
settings:
  monitor_all_containers: true
  monitor_all_swarm_services: true
  excluded_containers:
    - postgres-db
  excluded_swarm_services:
    - stack1_service1
    - stack2 
```

