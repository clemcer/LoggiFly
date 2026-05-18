

# Settings Overview

It's important to understand how settings can be applied on three different levels (this applies to both normal `settings` and `notifications` settings).

The three levels are:
- Global (`settings` / `notifications`)
- Per container (`containers`)
- Per trigger (`keywords` / `regex` / `container_event`)

::: details Here is an example of how settings can be applied on different levels

```yaml
containers:
  container1:
    notification_cooldown: 15
    title_template: "{container}: {keywords}"
    keywords:
      - keyword: "error"
        notification_cooldown: 0
        title_template: "Error in {container}"

settings:
  notification_cooldown: 5
  title_template: "{keywords} found in {container}"
```
:::

::: info
When the same setting is defined in multiple places like in the example above, the following priority applies:

`trigger > container > global`

Note that lists like `excluded_keywords` are merged, not overwritten.
:::

---


The following tables show which settings are available and where they can be configured:<br>
This is what the columns stand for:
- `G` = Global (`settings` or in case of notification settings: `notifications`)
- `C` = Per Container (`containers`)
- `T` = Per Trigger (`keywords` / `regex` / `container_event`)

### Global Only Settings
The following settings can only be configured globally under the `settings` section.

| Setting | G | C | T | Description |
|---------|---|---|---|-------------|
| `log_level`                      | ✅                   | –                             | –                     | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `multi_line_entries`            | ✅                   | –                             | –                      | Enable detection of multi-line log entries |
| `reload_config`                 | ✅                   | –                             | –                      | Automatically reload config on changes |
| `disable_start_message`         | ✅                   | –                             | –                      | Disable startup notification |
| `disable_shutdown_message`      | ✅                   | –                             | –                      | Disable shutdown notification |
| `disable_config_reload_message` | ✅                   | –                             | –                      | Disable notification when config is reloaded |
| `disable_monitor_event_message`| ✅                  | –                             | –                      | Disable notification when container monitoring starts/stops |
| `compact_summary_message`       | ✅                   | –                             | –                      | Formats the summary message in startup and config reload notifications with a comma-separated list of containers instead of a multi-line list|
| `monitor_all_containers`        | ✅                   | –                             | –                      | Monitor all containers on the host |
| `monitor_all_swarm_services`    | ✅                   | –                             | –                      | Monitor all swarm services on the host |
| `excluded_containers`           | ✅                   | –                             | –                      | List of containers that should not be monitored. To be used with `monitor_all_containers` |
| `excluded_swarm_services`       | ✅                   | –                             | –                      | List of swarm services that should not be monitored. To be used with `monitor_all_swarm_services` |

### Modular Settings

Most of these settings can be configured on all three levels.

| Setting | G | C | T | Description |
|---------|---|---|---|-------------|
| [`hosts`](./remote-hosts#option-2-assign-containers-to-hosts-via-the-hosts-field-of-the-container-configuration) | –     | ✅      | –             | Name of the host a container should be monitored on if monitoring multiple hosts |
| [`action`](./actions.md#container-actions)                        | –                    | –                             | ✅                      | Trigger container actions (restart/stop) |
| `disable_notifications`         | ✅                   | ✅                             | ✅                      | Disable notifications when keywords are found. Useful when you only want to trigger actions. |
| [`excluded_keywords`](./config_sections/settings#excluded-keywords) | ✅  | ✅  | ✅    | Log lines with these keywords will always be ignored | 
| `hide_regex_in_title`           | ✅                   | ✅                            | ✅                     | Don't show full regex pattern in found keywords in notification titles for cleaner look. Useful when using very long regexes.| 
| `regex_case_sensitive`          | ✅                   | ✅                            | ✅                     | Case sensitive regex matching |
| `notification_cooldown`         | ✅                   | ✅                            | ✅                     | Seconds between repeated alerts per container and keyword |
| `attachment_lines`              | ✅                   | ✅                            | ✅                     | Number of log lines to include in attachments |
| `attach_logfile`                | ✅                   | ✅                            | ✅                     | Attach log output to the notification (true/false) |
| `action_cooldown`               | ✅                   | ✅                            | ✅                      | Cooldown for triggering container actions per container and action (default: 300s, min: 10s) |
| `title_template`                | ✅                   | ✅                            | ✅                     | Template for the notification title. See [Customize Notifications](./customize-notifications/) |
| [`message_template`](./customize-notifications/) | ✅   | ✅                            | ✅                      | Template for notification messages |
| `olivetin_url`                  | ✅                   | ✅                            | ✅                      | URL of your OliveTin instance. See [Actions Guide](./actions.md#trigger-olivetin-actions) |
| `olivetin_username`             | ✅                   | ✅                            | ✅                      | Username for OliveTin authentication. See [Actions Guide](./actions.md#trigger-olivetin-actions) |
| `olivetin_password`             | ✅                   | ✅                            | ✅                      | Password for OliveTin authentication. See [Actions Guide](./actions.md#trigger-olivetin-actions) |
| `olivetin_actions`              | –                    | –                             | ✅                      | List of OliveTin actions to trigger. See [Actions Guide](./actions.md#trigger-olivetin-actions) |
| `olivetin_action_id`            | –                    | –                             | ✅                      | OliveTin action ID to trigger. See [Actions Guide](./actions.md#trigger-olivetin-actions) |

### Notifications Settings

Just like other settings you can set notification settings globally, per container or per trigger. 

Globally (`G`) you configure these settings under the respective notification service section under `notifications` and without the prefix (`ntfy_`, `apprise_`, `webhook_`) (see [Notifications Section](./config_sections/notifications)).

| Setting | G | C | T | Description |
|---------|---|---|---|-------------|
| `apprise_url`                  | ✅   | ✅                            | ✅                      | Apprise-compatible URL for notifications |
| `ntfy_url`                      | ✅      | ✅                            | ✅                 | ntfy server URL |
| `ntfy_topic`                    | ✅      | ✅                            | ✅                 | ntfy topic |
| `ntfy_priority`                 | ✅      | ✅                            | ✅                 | ntfy priority (1–5) |
| `ntfy_tags`                     | ✅      | ✅                            | ✅                 | Tags/emojis for ntfy notifications |
| `ntfy_token`                    | ✅      | ✅                            |✅                      | ntfy token for authentication |
| `ntfy_username`                 | ✅      | ✅                            | ✅                     | ntfy username for authentication |
| `ntfy_password`                 | ✅      | ✅                            | ✅                     | ntfy password for authentication |
| `ntfy_icon`                     | ✅      | ✅                            | ✅                     | ntfy icon for notifications |
| `ntfy_click`                    | ✅      | ✅                            | ✅                     | ntfy click action for notifications |
| `ntfy_markdown`                 | ✅      | ✅                            | ✅                     | ntfy markdown formatting for notifications |
| `ntfy_actions`                  | ✅      | ✅                            | ✅                     | ntfy actions for notifications |
| `ntfy_headers`                  | ✅      | ✅                            | ✅                     | ntfy headers for notifications |
| `webhook_url`                   | ✅      | ✅                            | ✅                     | Custom webhook URL for notifications |
| `webhook_headers`               | ✅      | ✅                            | ✅                     | Custom headers for webhook notifications |

> ✅ = supported<br>
> – = not supported

