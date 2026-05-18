---
title: Environment Variables
---

# Environment Variables

Except for container / keyword specific settings and regex patterns a lot of the settings can be configured via **Environment Variables**.


# General Settings

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `LOG_LEVEL`                     | Log Level for LoggiFly container logs.                    | INFO     |
| `MULTI_LINE_ENTRIES`            | When enabled the program tries to catch log entries that span multiple lines.<br>If you encounter bugs or you simply don't need it you can disable it.| True     |
| `RELOAD_CONFIG`               | When the config file is changed the program reloads the config | True  |
| `DISABLE_NOTIFICATIONS`       | Disable notifications when keywords are found. Useful when you only want to trigger actions.                                  | False     |
| `DISABLE_START_MESSAGE`          | Disable startup message.                                  | False     |
| `DISABLE_SHUTDOWN_MESSAGE`       | Disable shutdown message.                                 | False     |
| `DISABLE_CONFIG_RELOAD_MESSAGE`       | Disable message when the config file is reloaded.| False     |
| `DISABLE_MONITOR_EVENT_MESSAGE`       | Disable message when the monitoring of a container stops or starts.| False     |
| `COMPACT_SUMMARY_MESSAGE`       | Formats the summary message in startup and config reload notifications with a comma-separated list of containers instead of a multi-line list| False     |

## Notifications

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `NTFY_URL`                      | URL of your ntfy server instance                           | _N/A_    |
| `NTFY_TOKEN`                    | Authentication token for ntfy in case you need authentication.      | _N/A_    |
| `NTFY_USERNAME`                 | ntfy Username to use with the password in case you need authentication.             | _N/A_    |
| `NTFY_PASSWORD`                 | ntfy password to use with the username in case you need authentication.             | _N/A_    |
| `NTFY_TOPIC`                    | Notification topic for ntfy.                               | _N/A_  |
| `NTFY_TAGS`                     | [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications. | kite,mag  |
| `NTFY_PRIORITY`                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| `NTFY_ICON`                     | [Icon URL](https://docs.ntfy.sh/publish/?h=icon#icons) to display with the notification (defaults to LoggiFly logo) | _N/A_    |
| `NTFY_CLICK`                     | [URL to open](https://docs.ntfy.sh/publish/?h=click#click-action) when the notification is clicked | _N/A_    |
| `NTFY_MARKDOWN`                     | Enable [markdown formatting](https://docs.ntfy.sh/publish/?h=markdo#markdown-formatting) in message (true/false), defaults to false | False    |
| `APPRISE_URL`                   | Any [Apprise-compatible URL](https://github.com/caronc/apprise/wiki)  | _N/A_    |
| `WEBHOOK_URL`                   | URL of your custom webhook. | _N/A_    |

# Monitoring

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `LOGGIFLY_MODE`              | Set this variable to `swarm` when wanting to use LoggiFly in swarm mode | _N/A_     |
| `CONTAINERS`                    | A comma separated list of containers. These are added to the containers from the `config.yaml` (if you are using one).| _N/A_     |
| `SWARM_SERVICES`              |  A comma separated list of docker swarm services to monitor. | _N/A_     |
| `GLOBAL_KEYWORDS`       | Keywords that will be monitored for all containers. Overrides `global_keywords.keywords` from the `config.yaml`.| _N/A_     |
| `GLOBAL_KEYWORDS_WITH_ATTACHMENT`| Notifications triggered by these global keywords have a logfile attached. | _N/A_     |
| `MONITOR_ALL_CONTAINERS`      | Monitor all containers. | False     |
| `MONITOR_ALL_SWARM_SERVICES`  | Monitor all swarm services. | False     |
| `EXCLUDED_CONTAINERS`         | A comma separated list of containers that should not be monitored. To be used with `MONITOR_ALL_CONTAINERS` | _N/A_     |
| `EXCLUDED_SWARM_SERVICES`     | A comma separated list of swarm services that should not be monitored. To be used with `MONITOR_ALL_SWARM_SERVICES` | _N/A_     |


# Other Settings

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `EXCLUDED_KEYWORDS`       | Keywords that will always be ignored. Can be used to suppress notifications from irrelevant log lines | _N/A_     |
| `ATTACH_LOGFILE`                | Attach a Logfile to *all* notifications. | True    |
| `ATTACHMENT_LINES`              | Define the number of Log Lines in the attachment file     | 20     |
| `NOTIFICATION_COOLDOWN`         | Cooldown period (in seconds) per container per keyword before a new message can be sent  | 5        | 
| `ACTION_COOLDOWN`         | Cooldown period (in seconds) before the next container action can be performed. Always at least 10s. (`action_keywords` are only configurable in YAML)  | 300        |
| `TITLE_TEMPLATE`         | Template for the notification title (see [customize-notifications](./customize-notifications/)) | _N/A_        |
| `MESSAGE_TEMPLATE`         | Template for the notification message (see [customize-notifications](./customize-notifications/)) | _N/A_        |
| `HIDE_REGEX_IN_TITLE`         | Exclude regex from the found keywords in the notification title for a cleaner look. Useful when using very long regexes.| False     |
| `REGEX_CASE_SENSITIVE`         | Case sensitive regex matching. | False     |
| `OLIVETIN_URL`         | URL of your OliveTin instance. | _N/A_        |
| `OLIVETIN_USERNAME`         | Username for your OliveTin instance. | _N/A_        |
| `OLIVETIN_PASSWORD`         | Password for your OliveTin instance. | _N/A_        |
