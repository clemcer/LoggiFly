---
title: Settings & Defaults
---

# `global:`

The `global:` section holds all **inheritable** settings under `global.defaults`. These are the global baseline values that cascade down through sources, rules, and individual keywords. Any setting defined here can be overridden at a more specific level.

Additionally you can define **keywords** under `global.keywords` that are applied to every matched target across all sources.


```yaml
global:
  keywords:
    # ...
  defaults:
    # ...
```

## `keywords:`

```yaml
global:
  # --- Global keywords --------------------------------------------------
  # Applied to EVERY matched target across ALL sources (containers + swarm).
  # Combined with source-level keywords and rule-level keywords.
  keywords:
    - keyword: "critical"
    - keyword: "out of memory"

```
::: info
For more general details on keywords, see [Keywords & Triggers](./keywords-and-triggers).<br>
For more details on how keywords are merged across levels, see [How triggers are merged across levels](./keywords-and-triggers#how-triggers-are-merged-across-levels).
:::

## `defaults:` {#defaults}

The `defaults:` section holds all **inheritable** settings. All of the following settings can be overridden at a more specific level:

::: details `config.yaml` reference
```yaml
global:

  defaults:

    # --- Behavioral defaults ----------------------------------------------

    # Minimum seconds between repeated triggers for the same keyword on the
    # same target. 0 = no cooldown (default).
    trigger_cooldown: 0

    # Minimum seconds between repeated container actions on the same target.
    # Default: 60. Minimum enforced: 10.
    container_action_cooldown: 60

    # Attach recent log lines as a file to the notification.
    attach_logfile: false
    attachment_lines: 20                # number of lines to include

    # Hide the full regex pattern in the notification title.
    # Useful for long/complex patterns.
    hide_full_regex: false

    # Regex patterns are case-sensitive by default.
    regex_case_sensitive: true

    # Suppress notifications from triggers (eg. keyword matches) entirely.
    # Useful for action-only workflows where you don't need the notification.
    disable_trigger_notifications: false

    # When a single log line matches multiple keywords, send one notification
    # per keyword match (false, default) or merge into one notification (true).
    merge_matches: false

    # Keywords/patterns that suppress a trigger when found in the same log line.
    # Accepts plain strings, { keyword: ... }, and { regex: ... }.
    # Combined with ignore_keywords from all other levels.
    ignore_keywords:
      - debug
      - keyword: trace
      - regex: ^\[HEALTH\]


    # --- Templates --------------------------------------------------------
    # Jinja2 syntax: {{ variable }}. Variable names listed in the docs:
    # https://clemcer.github.io/loggifly/guide/customize-notifications/

    title_template: "{{ container_name }}: {{ keywords }}"
    message_template: |
      Container: {{ container_name }}
      Keywords:  {{ keywords }}
      Time:      {{ datetime }}
      Log:       {{ log_entry }}

    # --- OliveTin integration ---------------------------------------------
    olivetin_url: "http://olivetin:1337"
    olivetin_username: "admin"
    olivetin_password: "secret"

    # --- Notification channel settings ------------------------------------
    # Rarely set here since the notifications section already handles the global settings
    # However, you can set these per rule or trigger as well to override the global settings
    # ntfy_url:
    # ntfy_topic:
    # ntfy_priority:
    # ntfy_tags:
    # ntfy_token:
    # ntfy_username:
    # ntfy_password:
    # ntfy_icon:
    # ntfy_click:
    # ntfy_markdown:
    # ntfy_actions:
    # ntfy_headers:
    # apprise_url:
    # webhook_url:
    # webhook_headers:

```
:::

<!-- ### Fields Reference -->

::: details Fields Reference

| Field | Default | Description |
|-------|---------|-------------|
| `trigger_cooldown` | `0` | Seconds between repeated triggers for the same keyword on the same target. `0` disables cooldown. Applies to both keyword matches and container events. |
| `container_action_cooldown` | `60` | Minimum seconds between repeated container actions on the same target. Minimum enforced: `10`. |
| `attach_logfile` | `false` | Attach recent log lines as a file to the notification. |
| `attachment_lines` | `20` | Number of log lines to include in the log attachment. |
| `hide_full_regex` | `false` | In notification titles, show only named capture group values instead of the full matched regex pattern. Useful for long or complex patterns. |
| `regex_case_sensitive` | `true` | Whether `regex:` patterns are case-sensitive. Has no effect on `keyword:` items, which are always case-insensitive. |
| `disable_trigger_notifications` | `false` | Suppress the notification when a trigger fires. Actions (container actions, OliveTin) are still executed. Useful for action-only workflows. |
| `merge_matches` | `false` | When `false` (default), each matching keyword in a log line fires its own independent notification. When `true`, all matches from a single log line are merged into one notification (v1 behavior). |
| `ignore_keywords` | — | Keywords or regex patterns that suppress a trigger when found in the same log line. Combined with ignore_keywords from all other levels. |
| `title_template` | — | Jinja2 template for the notification title. See [Customize Notifications](../customize-notifications/). |
| `message_template` | — | Jinja2 template for the notification message body. See [Customize Notifications](../customize-notifications/). |
| `ntfy_url` | — | ntfy server URL. |
| `ntfy_topic` | — | ntfy topic to publish to. |
| `ntfy_priority` | — | ntfy priority (`1`–`5` or `min`/`low`/`default`/`high`/`max`). |
| `ntfy_tags` | — | Comma-separated ntfy emoji tags (e.g. `warning,fire`). |
| `ntfy_token` | — | ntfy authentication token. |
| `ntfy_username` | — | ntfy username (basic auth). |
| `ntfy_password` | — | ntfy password (basic auth). |
| `ntfy_icon` | — | URL of an icon to display with the notification. |
| `ntfy_click` | — | URL to open when the notification is clicked. |
| `ntfy_markdown` | — | Render notification body as Markdown. |
| `ntfy_actions` | — | List of ntfy action buttons. See [Notifications](./notifications#ntfy-actions). Combined with action buttons from all levels. |
| `ntfy_headers` | — | Custom HTTP headers for ntfy requests. Combined with headers from all levels (more specific levels add or override individual keys). |
| `apprise_url` | — | Apprise-compatible notification URL. See [Notifications](./notifications#apprise). |
| `webhook_url` | — | HTTP endpoint to POST notification payloads to. |
| `webhook_headers` | — | Custom headers for webhook requests. Combined with headers from all levels (more specific levels add or override individual keys). |
| `olivetin_url` | — | Base URL of an OliveTin instance. See [Actions](../actions#olivetin-actions). |
| `olivetin_username` | — | Username for OliveTin authentication. |
| `olivetin_password` | — | Password for OliveTin authentication. |

:::


## Inheritance & Merging of Settings

All of the settings from `global.defaults:` can be defined at multiple levels. The levels, from lowest to highest precedence are:

| # | Level | Configuration Section |
|---|---|---|
| 1 | Global Level | `global.defaults` |
| 2 | Source Level | `containers.defaults` / `swarm.defaults` |
| 3 | [Rule Level](./containers-and-rules#rules) | `containers.rules[*]` |
| 4 | [Group Level](./containers-and-rules#groups) | `containers.groups[*]` |
| 5 | [Docker Labels](./label-config) | `loggifly.<setting>=<value>` on a container |
| 6 | [Per-trigger settings](./keywords-and-triggers#per-keyword-defaults-settings) | `keyword` or `container_event` item settings |

::: info How settings are combined across levels

| Setting | Behavior |
|---|---|
| `ignore_keywords`, `ntfy_actions` | Combined from all levels, duplicates are skipped |
| `ntfy_headers`, `webhook_headers` | Combined from all levels (more specific levels add or override individual keys) |
| Everything else | Most specific level wins. Later rules and later triggers take precedence over earlier ones. |

Note that the [`notifications`](./notifications) block is not merged with notification settings from `defaults`, it essentially acts as a base level or fallback.

:::

### Example

```yaml
# global level
global:
  defaults:
    ntfy_priority: 1

# source level
containers:
  defaults:
    ntfy_priority: 2 # overrides the global level

  # rule level
  rules:
    - container_name: my-app
      ntfy_priority: 3 # overrides the source level
      keywords:
        - keyword: "error"
          ntfy_priority: 5 # overrides the rule level

    # inherits from source.defaults: ntfy_priority: 2
    - container_name: my-other-app
      keywords:
        - keyword: "critical"

swarm:
  rules:
    # inherits from global.defaults: ntfy_priority: 1
    - service_name: my-service
      keywords:
        - keyword: "critical"
```
- For the container `my-app` the `ntfy_priority` will be `3` unless the keyword `error` matches, in which case `5` is used for that notification.
- For the container `my-other-app` the `ntfy_priority` will be `2`.
- For the swarm service `my-service` the `ntfy_priority` will be `1`.

For how merging works when a container matches **multiple rules**, see [Multi-Rule Merging](./containers-and-rules#multi-rule-merging).

