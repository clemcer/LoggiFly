---
title: Environment Variables
---

# Environment Variables

While you can configure a lot of settings via **Environment Variables**, you can not create multiple rules or apply settings on different levels like you can do in the `config.yaml`.

## Settings

Maps to the `settings:` section in the config.yaml.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------|
| `LOG_LEVEL` | `string` | `INFO` | Log verbosity level. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`. | `settings.log_level` |
| `MULTI_LINE_ENTRIES` | `bool` | `true` | Group multi-line log entries before keyword matching. LoggiFly automatically detects the log format. | `settings.multi_line_entries` |
| `SYSTEM_NOTIFICATIONS_START` | `bool` | `true` | Whether to send a notification when LoggiFly starts. | `settings.system_notifications.start` |
| `SYSTEM_NOTIFICATIONS_SHUTDOWN` | `bool` | `true` | Whether to send a notification when LoggiFly shuts down. | `settings.system_notifications.shutdown` |
| `SYSTEM_NOTIFICATIONS_CONFIG_RELOAD` | `bool` | `true` | Whether to send a notification when the config file is reloaded. | `settings.system_notifications.config_reload` |
| `SYSTEM_NOTIFICATIONS_MONITOR_EVENT` | `bool` | `true` | Whether to send a notification when a container starts or stops being monitored. | `settings.system_notifications.monitor_event` |
| `SYSTEM_NOTIFICATIONS` | `bool` | `true` | Shortcut to enable or disable all system notifications. | `settings.system_notifications` |
| `COMPACT_SUMMARY_MESSAGE` | `bool` | `false` | Send a shorter summary notification instead of a full message. | `settings.compact_summary_message` |
| `RELOAD_CONFIG` | `bool` | `true` | Automatically reload configuration when the config file changes. | `settings.reload_config` |

## Global Keywords

Maps to the `global.keywords:` section in the config.yaml.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------|
| `GLOBAL_KEYWORDS` | `string (comma-separated)` | `–` | Keywords to watch for across all monitored containers. | `global.keywords` |

## Global Defaults 

Maps to the `global.defaults:` section in the config.yaml.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------|
| `IGNORE_KEYWORDS` | `string (comma-separated)` | `–` | Keywords to suppress. Matching log lines will not trigger notifications (or anything else like actions). | `global.defaults.ignore_keywords` |
| `TITLE_TEMPLATE` | `string` | `–` | [Template](./customize-notifications/#template-fields-reference) for the notification title. Use <code v-pre>{{ variable }}</code> placeholders (e.g. <code v-pre>{{ container_name }}</code>, <code v-pre>{{ keyword }}</code>). | `global.defaults.title_template` |
| `MESSAGE_TEMPLATE` | `string` | `–` | [Template](./customize-notifications/#template-fields-reference) for the notification message body. Use <code v-pre>{{ variable }}</code> placeholders (e.g.<code v-pre>{{ log_entry }}</code>, <code v-pre>{{ keyword }}</code>). | `global.defaults.message_template` |
| `OLIVETIN_URL` | `string` | `–` | Base URL of the OliveTin instance to trigger actions on. | `global.defaults.olivetin_url` |
| `OLIVETIN_USERNAME` | `string` | `–` | Username for OliveTin authentication. | `global.defaults.olivetin_username` |
| `OLIVETIN_PASSWORD` | `string` | `–` | Password for OliveTin authentication. | `global.defaults.olivetin_password` |
| `ATTACH_LOGFILE` | `bool` | `false` | Attach recent log lines as a file to the notification. | `defaults.attach_logfile` |
| `TRIGGER_COOLDOWN` | `int` | `0` | Minimum seconds between repeated triggers for the same keyword on the same target. `0` disables cooldown. | `global.defaults.trigger_cooldown` |
| `CONTAINER_ACTION_COOLDOWN` | `int` | `60` | Minimum seconds between repeated container actions (restart/stop) on the same target. | `global.defaults.container_action_cooldown` |
| `ATTACHMENT_LINES` | `int` | `20` | Number of log lines to include in the log attachment. | `global.defaults.attachment_lines` |
| `HIDE_FULL_REGEX` | `bool` | `false` | In notifications, hide the full regex match and only show named capturing groups. | `global.defaults.hide_full_regex` |
| `REGEX_CASE_SENSITIVE` | `bool` | `true` | Whether regex patterns are case-sensitive. | `global.defaults.regex_case_sensitive` |
| `DISABLE_TRIGGER_NOTIFICATIONS` | `bool` | `false` | Suppress all notifications. Useful when only container actions or OliveTin actions are needed. | `global.defaults.disable_trigger_notifications` |
| `MERGE_MATCHES` | `bool` | `false` | Combine multiple keyword matches from the same log entry into a single notification. | `global.defaults.merge_matches` |

## Notifications

Maps to the `notifications:` section in the config.yaml.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------|
| `NTFY_TAGS` | `string` | `–` | Comma-separated Ntfy tags or emoji shortcodes to include in the notification header. | `notifications.ntfy.tags` |
| `NTFY_TOPIC` | `string` | `–` | Ntfy topic to publish notifications to. | `notifications.ntfy.topic` |
| `NTFY_PRIORITY` | `string` / `int` | `–` | Notification priority. One of `min`, `low`, `default`, `high`, `max` (or 1–5). | `notifications.ntfy.priority` |
| `NTFY_URL` | `string` | `–` | Base URL of the Ntfy server (e.g. `https://ntfy.sh`). | `notifications.ntfy.url` |
| `NTFY_TOKEN` | `string` | `–` | Authentication token for Ntfy. | `notifications.ntfy.token` |
| `NTFY_USERNAME` | `string` | `–` | Username for Ntfy basic authentication. | `notifications.ntfy.username` |
| `NTFY_PASSWORD` | `string` | `–` | Password for Ntfy basic authentication. | `notifications.ntfy.password` |
| `NTFY_ICON` | `string` | `–` | URL of an icon to display with the notification. | `notifications.ntfy.icon` |
| `NTFY_CLICK` | `string` | `–` | URL to open when the notification is clicked. | `notifications.ntfy.click` |
| `NTFY_MARKDOWN` | `bool` | `–` | Render the notification body as Markdown. | `notifications.ntfy.markdown` |
| `APPRISE_URL` | `string` | `–` | Apprise-compatible notification URL (supports 100+ services). | `notifications.apprise.url` |
| `WEBHOOK_URL` | `string` | `–` | HTTP endpoint to POST notification payloads to. | `notifications.webhook.url` |


## Containers

Shortcuts to configure container monitoring without a config file. Maps into the `containers:` section.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------|
| `CONTAINERS` | `string (comma-separated)` | `–` | Container names to monitor with default keyword settings. | `containers.rules.0.match.include.container_names` |
| `CONTAINERS_KEYWORDS` | `string (comma-separated)` | `–` | Keywords to watch for across all monitored containers. | `containers.keywords` |
| `CONTAINERS_CONTAINER_EVENTS` | `string (comma-separated)` | `–` | Docker container events to monitor (e.g. `start,stop,die`). | `containers.container_events` |
| `CONTAINERS_SCOPE_HOSTS` | `string (comma-separated)` | `–` | Docker hosts to restrict container monitoring to. | `containers.scope.hosts` |
| `CONTAINERS_NEVER_MONITOR` | `string (comma-separated)` | `–` | Container names to never monitor. | `containers.never_monitor.container_names` |

## Swarm

Shortcuts to configure Docker Swarm service monitoring without a config file. Maps into the `swarm:` section.

| Variable | Type | Default | Description | Maps to |
|----------|------|---------|-------------|-------------| 
| `SWARM_SERVICES` | `string (comma-separated)` | `–` | Swarm service names to monitor with default keyword settings. | `swarm.rules.0.match.include.service_names` |
| `SWARM_STACKS` | `string (comma-separated)` | `–` | Swarm stack names to monitor with default keyword settings. | `swarm.rules.1.match.include.stack_names` |
| `SWARM_KEYWORDS` | `string (comma-separated)` | `–` | Keywords to watch for across all monitored Swarm services. | `swarm.keywords` |
| `SWARM_CONTAINER_EVENTS` | `string (comma-separated)` | `–` | Docker events to monitor for Swarm services. | `swarm.container_events` |
| `SWARM_SCOPE_HOSTS` | `string (comma-separated)` | `–` | Docker hosts to restrict Swarm monitoring to. | `swarm.scope.hosts` |
| `SWARM_SERVICES_NEVER_MONITOR` | `string (comma-separated)` | `–` | Swarm service names to never monitor. | `swarm.never_monitor.service_names` |
| `SWARM_STACKS_NEVER_MONITOR` | `string (comma-separated)` | `–` | Swarm stack names to never monitor. | `swarm.never_monitor.stack_names` |

## Advanced

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CONFIG_PATH` | `string` | `/config/config.yaml` | Path to the YAML config file inside the container. |
| `DOCKER_HOST` | `string` | `–` | Docker socket or TCP address to connect to (e.g. `tcp://remote-host:2375`). Defaults to the local socket. |
| `LOGGIFLY_MODE` | `string` | `–` | Set to `swarm` to get additional context in notifications about which node the container that has triggered a notification is running on. |
| `STRICT_CONFIG` | `bool` | `true` | Make unknown config fields raise an error instead of a warning. |
| `DEBUG_TARGET_CONFIG` | `bool` | `false` | Enable detailed logging showing the effective target config for each target (debug logging needs to be enabled) |
| `ENABLE_HEALTHCHECK` | `bool` | `false` | Enable the file-based healthcheck heartbeat. |
| `HEARTBEAT_PATH` | `string` | `/dev/shm/loggifly-heartbeat` | Path to the heartbeat file written by the healthcheck mechanism. |
| `HEARTBEAT_INTERVAL` | `int` | `60` | Interval in seconds between heartbeat file writes. |
| `MAX_TRIGGER_WORKERS` | `int` | `8` | Maximum number of concurrent worker threads for processing triggers. |
| `CLEANUP_THRESHOLD_HOURS_CONFIGURED` | `int` | `168` | Hours of inactivity before a configured but stale container monitor is cleaned up. |
| `CLEANUP_THRESHOLD_HOURS_UNCONFIGURED` | `int` | `24` | Hours of inactivity before an unconfigured container monitor is cleaned up. |
| `CLEANUP_INTERVAL_MINUTES` | `int` | `60` | How often (in minutes) the stale monitor cleanup task runs. |
