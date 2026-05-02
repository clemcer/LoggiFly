---
title: Migrate to v2
outline: [2, 3]
---

# Migrate to v2

v2 is a major redesign of the configuration schema. The structure of nearly every top-level config key changed, several fields were renamed, and some default values shifted.

::: tip Use the migration script first
A migration script handles most of the mechanical conversion automatically. Start there, then use this guide to review what changed and catch anything that needs manual attention.
:::


## What's New in v2

Before diving into what changed, here's which new features you can expect in v2:

- **Flexible rule-based targeting**: rules replace the old per-container dict. Match containers by glob pattern (`web-*`, `*-db`, `*`), combine multiple include and exclude patterns per rule, and let one rule cover dozens of containers at once. ([docs](./config/containers-and-rules#rules))

- **Rule groups for shared settings**: use `groups` to apply shared settings like scope, defaults, or keywords to a set of rules without repeating them on every rule ([docs](./config/containers-and-rules#groups))

- **New threshold-based triggering (`trigger_on`)**: a trigger can now require N matches within a time window before firing. Applies to both log keyword matches and container events. ([docs](./config/keywords-and-triggers#threshold-based-triggering-with-trigger-on))

- **Jinja2 templates**: `title_template` and `message_template` now use Jinja2 syntax (`{{ variable }}` instead of `{variable}`), unlocking filters, conditionals, and more. The migration script handles this conversion automatically ([docs](./customize-notifications/#jinja2-features)).


## Migration Script

The recommended first step is running the migration script. It converts your v1 `config.yaml` to v2 format automatically.

### Run with Docker (recommended)

```bash
docker run --rm \
  -v /path/to/your/config/dir:/config \
  ghcr.io/clemcer/loggifly-migrate:v1-to-v2
```

By default it reads `/config/config.yaml` and writes `/config/configv2.yaml`. Your original file is never modified.

To specify custom paths (inside the container):

```bash
docker run --rm \
  -v /path/to/your/config/dir:/config \
  ghcr.io/clemcer/loggifly-migrate:v1-to-v2 \
  -i /config/my_config.yaml -o /config/my_configv2.yaml
```

### After running the script

**Check the script's log output**: warnings indicate fields that could not be migrated automatically and require manual attention.

Then work through the [Behavioral Changes](#behavioral-changes) section below. These are the things the script cannot decide for you.

::: warning Swarm users: check your service vs. stack names
Every key under `swarm_services:` is assumed to be a **service name** and converted to a rule with `service_name`. If any of your keys were actually stack names, manually change those rules to use `stack_names` instead of `service_names`.
:::

::: tip `STRICT_CONFIG=false`
v2 enables strict config validation by default so that unknown or misspelled fields cause a startup failure. Setting `STRICT_CONFIG=false` will ignore those errors and only log warnings.<br>
If you use the migration script this should however not be necessary.
:::

---

## Behavioral Changes

These are the changes the script cannot handle. They require your judgment. **Review all of these even if the script ran cleanly.**

### `merge_matches` now defaults to `false`

In v1, when a single log line matched multiple keywords, all matches were merged into one notification. In v2, the default is **one notification per keyword match**.

If you have multiple keywords configured for any container, you will receive separate notifications for each matched keyword unless you opt back in.

To restore v1 behavior globally:

```yaml
global:
  defaults:
    merge_matches: true
```

You can also set `merge_matches` at the rule level or per-keyword for fine-grained control.

### `regex_case_sensitive` now defaults to `true`

In v1, regex matching was case-insensitive by default. In v2 it defaults to case-sensitive.

This only affects `regex:` items and `all_of` groups containing `regex:` members. Plain `keyword:` items are always case-insensitive regardless of this setting.

To restore v1 behavior:

```yaml
global:
  defaults:
    regex_case_sensitive: false
```


### `trigger_cooldown` now defaults to `0` (was `notification_cooldown: 5`)

The cooldown between repeated triggers is now `0` seconds by default instead of `5`. It was also renamed from `notification_cooldown` to `trigger_cooldown` to reflect that it also applies for triggers when notifications are disabled.

To restore v1 behavior:

```yaml
global:
  defaults:
    trigger_cooldown: 5
```

### `container_action_cooldown` now defaults to `60s` (was `action_cooldown: 300s`)

The default for the cooldown between repeated container actions dropped from `300` seconds to `60`.

### Template syntax changed to Jinja2

`title_template` and `message_template` now use Jinja2 syntax. Replace `{variable}` with <code v-pre>{{ variable }}</code>:

```yaml
# v1
title_template: "[{container_name}] {keyword}"
message_template: "{log_entry}"

# v2
title_template: "[{{ container_name }}] {{ keyword }}"
message_template: "{{ log_entry }}"
```

This applies everywhere templates are used: `global.defaults`, `containers.defaults`, rule config, per-keyword config, and Docker labels. 

There were also some template variable renames:
- `action_result_message` → `container_action_result_message`
- `action_type` → `container_action_type`
- `action_string` → `container_action_string`
- `action_target` → `container_action_target`
- `action_succeeded` → `container_action_succeeded`


The migration script handles this conversion automatically for config files. If you set templates via **Docker labels**, update them manually:

```yaml
labels:
  # v1
  loggifly.keywords.0.title_template: "{container_name}: Critical Alert"

  # v2
  loggifly.keywords.0.title_template: "{{ container_name }}: Critical Alert"
```

Jinja2 also unlocks filters, conditionals, and more (see [Customize Notifications](./customize-notifications/#jinja2-features) for details).



## Config Structure Changes

The script handles all of these automatically. This section explains what changed and why, so you can verify the output and understand the new structure.

### New `global.defaults:` section

In v1, settings that can be set on multiple levels like `attach_logfile`, `title_template`, `ntfy_priority`, etc. lived under `settings:`. In v2, `settings:` is narrowed to application-only settings, and everything inheritable moved to `global.defaults:`.

```yaml
# v1
settings:
  notification_cooldown: 10
  attach_logfile: true
  ntfy_priority: 4
  title_template: "[{container_name}] {keywords}"

# v2
global:
  defaults:
    trigger_cooldown: 10
    attach_logfile: true
    ntfy_priority: 4
    title_template: "[{{ container_name }}] {{ keywords }}"
```

::: info
For more information on how these settings are merged across levels, see [Inheritance & Merging of Settings](./config/global#inheritance-merging-of-settings).
:::


### `global_keywords:` → `global.keywords`

```yaml
# v1
global_keywords:
  keywords:
    - keyword: critical

# v2
global:
  keywords:
    - keyword: critical
```

### `containers:` is now a source object and allows for more flexible matching

In v1, `containers:` was a dict of named container configs. In v2 it is a source configuration object. Per-container config lives inside `containers.rules`.

```yaml
# v1
containers:
  my-app:
    keywords:
      - keyword: error

# v2
containers:
  rules:
    - match:
        include:
          container_names: 
            - "my-app"
            - "database-*"
        exclude:
          container_names:
            - "*temp*"
      keywords:
        - keyword: error
          
    - container_name: my-app   # shorthand for match.include.container_names: ["my-app"]
      keywords:
        - keyword: error
    
    # monitor ALL containers with keyword "critical"
    - container_name: "*"
      keywords:
        - keyword: critical
```

Rules support glob patterns: `container_names: ["web-*", "*-api"]` matches any container whose name fits. 

::: info 
For more details on what you can configure under `containers`, see [Containers & Rules](./config/containers-and-rules).
:::


### Deprecated settings

The following settings are deprecated:

- `monitor_all_containers`
- `excluded_containers`
- `monitor_all_swarm_services`
- `excluded_swarm_services`

::: details The new configuration system replaces these settings with more flexible matching options.

```yaml
containers:
  rules:
    - match:
        include:
          container_names: ["*"]
        exclude:
          container_names: ["*-temp"]
      keywords:
        - keyword: error
```
:::

### `swarm_services:` → `swarm:`

The top-level key changed and the structure mirrors `containers:`.

```yaml
# v1
swarm_services:
  my-service:
    keywords:
      - keyword: timeout

# v2
swarm:
  rules:
    - match:
        include:
          service_names: ["my-service"]
        exclude:
          stack_names: ["*-temp"]
      keywords:
        - keyword: timeout

    # shorthand for match.include.service_names: ["my-service"]
    - service_name: my-service
      keywords:
        - keyword: timeout
```

### `hosts:` block → `scope.hosts` / `groups`

The v2 equivalent to the deprecated `hosts:` block is to use `containers.groups:` to share the host scope without repeating it on every rule. 
Groups are explained in more detail in [Containers & Rules](./config/containers-and-rules#groups).

```yaml
# v1
hosts:
  my-remote-host:
    containers:
      my-app:
        keywords:
          - keyword: error
      my-other-app:
        keywords:
          - keyword: warning

# v2: all rules in this group share the same scope
containers:
  groups:
    - scope:
        hosts: ["my-remote-host"]
      rules:
        - container_name: my-app
          keywords:
            - keyword: error
        - container_name: my-other-app
          keywords:
            - keyword: warning
```
`groups` also exist for `swarm:`.

### `settings.excluded_containers` → `containers.never_monitor`

```yaml
# v1
settings:
  excluded_containers: ["loggifly", "socket-proxy"]

# v2
containers:
  never_monitor:
    container_names: ["loggifly", "socket-proxy"]
```

`never_monitor` supports glob patterns and takes precedence over `loggifly.monitor=true` labels.

### `settings:` narrowed

`settings:` now contains only non-inheritable application settings:

```yaml
settings:
  log_level: INFO
  multi_line_entries: true
  reload_config: true
  system_notifications: true
```

The four separate `disable_start_message` / `disable_shutdown_message` / `disable_config_reload_message` / `disable_monitor_event_message` fields are replaced by a single `system_notifications` field:

```yaml
settings:
  system_notifications: false   # disable all system notifications

  # or selectively:
  system_notifications:
    start: true
    shutdown: true
    config_reload: false
    monitor_event: true
```

---

## Field Renames

These renames apply everywhere the field appears: `global.defaults:`, source-level `defaults:`, rule config, trigger configs (`keywords` or `container_events`). The migration script handles all of these.

::: details Field rename reference table
| v1 field | v2 field | Notes |
|---|---|---|
| `action` | `container_action` | Does **not** affect `action:` inside `ntfy_actions` objects |
| `notification_cooldown` | `trigger_cooldown` | Now applies to `container_events` too; default changed to `0` |
| `action_cooldown` | `container_action_cooldown` | Default changed from `300s` to `60s` |
| `hide_regex_in_title` | `hide_full_regex` | |
| `excluded_keywords` | `ignore_keywords` | Now supports `{regex: ...}` items |
| `keyword_group` | `all_of` | Members can now be `{keyword: ...}` or `{regex: ...}` |
| `disable_notifications` | `disable_trigger_notifications` | |
| `swarm_services` | `swarm` | Top-level key only |

:::

---

## Environment Variables

::: details Renamed Environment Variables
| v1 | v2 |
|---|---|
| `EXCLUDED_CONTAINERS` | `CONTAINERS_NEVER_MONITOR` |
| `EXCLUDED_SWARM_SERVICES` | `SWARM_SERVICES_NEVER_MONITOR` & `SWARM_STACKS_NEVER_MONITOR` |
| `HIDE_REGEX_IN_TITLE` | `HIDE_FULL_REGEX` |
| `EXCLUDED_KEYWORDS` | `IGNORE_KEYWORDS` |
| `NOTIFICATION_COOLDOWN` | `TRIGGER_COOLDOWN` |
| `ACTION_COOLDOWN` | `CONTAINER_ACTION_COOLDOWN` |
| `DISABLE_NOTIFICATIONS` | `DISABLE_TRIGGER_NOTIFICATIONS` |
| `DISABLE_START_MESSAGE` | `SYSTEM_NOTIFICATIONS_START` |
| `DISABLE_SHUTDOWN_MESSAGE` | `SYSTEM_NOTIFICATIONS_SHUTDOWN` |
| `DISABLE_CONFIG_RELOAD_MESSAGE` | `SYSTEM_NOTIFICATIONS_CONFIG_RELOAD` |
| `DISABLE_MONITOR_EVENT_MESSAGE` | `SYSTEM_NOTIFICATIONS_MONITOR_EVENT` |

:::

::: details Removed env vars

| v1 | Replacement |
|---|---|
| `MONITOR_ALL_CONTAINERS` | Add a wildcard to `CONTAINERS` (`CONTAINERS=*`) |
| `MONITOR_ALL_SWARM_SERVICES` | Add a wildcard to `SWARM_SERVICES` (`SWARM_SERVICES=*`) |
| `GLOBAL_KEYWORDS_WITH_ATTACHMENT` | No direct replacement, you can attach logfiles to *all* notifications by setting `ATTACH_LOGFILE=true` |

:::


::: details New env vars

| Env var | Maps to | Notes |
|---|---|---|
| `CONTAINERS_KEYWORDS` | `containers.keywords` | Comma-separated keywords applied to all matched containers |
| `CONTAINERS_CONTAINER_EVENTS` | `containers.container_events` | Comma-separated events |
| `CONTAINERS_SCOPE_HOSTS` | `containers.scope.hosts` | Comma-separated glob list |
| `SWARM_STACKS` | `swarm.rules` | Comma-separated stack names |
| `SWARM_KEYWORDS` | `swarm.keywords` | Comma-separated |
| `SWARM_CONTAINER_EVENTS` | `swarm.container_events` | Comma-separated |
| `SWARM_SCOPE_HOSTS` | `swarm.scope.hosts` | Comma-separated |
| `SYSTEM_NOTIFICATIONS` | `system_notifications` | Shortcut to enable or disable all system notifications |
| `CONFIG_PATH` | – | Overrides the default `/config/config.yaml` |
| `STRICT_CONFIG` | – | `true` (default) = startup failure on unknown fields; `false` = warn and continue |
| `MAX_TRIGGER_WORKERS` | – | Thread pool size | Default `8` |
| `DEBUG_TARGET_CONFIG` | — | Log the effective config of all monitored containers when monitoring starts (debug logging needs to be enabled) |

:::

`GLOBAL_KEYWORDS` still works the same but now maps to `global.keywords` instead of `global_keywords.keywords`.


### Config file path

The legacy config path `/app/config.yaml` is no longer supported. LoggiFly now reads `/config/config.yaml` by default. Override with `CONFIG_PATH`:

```yaml
environment:
  CONFIG_PATH: /config/my-custom-config.yaml
```

---

## Docker Labels

Label-based configuration (`loggifly.monitor=true`) still works. Update field names in your labels to match v2:

::: details Label field renames

| v1 label key | v2 label key |
|---|---|
| `loggifly.keywords.0.action` | `loggifly.keywords.0.container_action` |
| `loggifly.keywords.0.action_cooldown` | `loggifly.keywords.0.container_action_cooldown` |
| `loggifly.keywords.0.notification_cooldown` | `loggifly.keywords.0.trigger_cooldown` |
| `loggifly.keywords.0.hide_regex_in_title` | `loggifly.keywords.0.hide_full_regex` |
| `loggifly.keywords.0.excluded_keywords` | `loggifly.keywords.0.ignore_keywords` |
| `loggifly.keywords.0.keyword_group` | `loggifly.keywords.0.all_of` |

:::

New label: if `loggifly.ignore_config=true` is set, the `config.yaml` and environment variables are ignored and the label config is used exclusively.

Also the new **Jinja2 templating syntax** is used for `title_template` and `message_template` fields. See [Template syntax changed to Jinja2](#template-syntax-changed-to-jinja2)


---

## Full Config Example: Before & After

::: details v1 config
```yaml
settings:
  excluded_containers: ["loggifly"]
  notification_cooldown: 5
  action_cooldown: 300
  hide_regex_in_title: true
  regex_case_sensitive: false
  excluded_keywords:
    - keyword: debug

global_keywords:
  keywords:
    - keyword: "critical"

hosts:
  nas:
    containers:
      postgres:
        keywords:
          - keyword: "FATAL"
          - keyword: "could not connect"
      nginx:
        keywords:
          - keyword: "upstream timed out"

containers:
  vaultwarden:
    ntfy_tags: "closed_lock_with_key"
    ntfy_priority: 5
    ntfy_topic: security
    keywords:
      - regex: '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Username or password is incorrect. Try again. IP: (\d{1,3}(?:\.\d{1,3}){3}). Username: ([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        message_template: |
          Failed login!
          Email: '{2}'
          IP Address: {3}
          Time: {1}
        title_template: "Failed Vaultwarden login"
        ntfy_tags: "rotating_light"
    container_events:
      - event: crash
        action: restart

swarm_services:
  app_worker:
    keywords:
      - keyword: "timeout"
      - keyword: "connection refused"

notifications:
  ntfy:
    url: "http://ntfy.example.com"
    topic: "alerts"
```
:::

::: details v2 config
```yaml
version: 2

global:
  defaults:
    trigger_cooldown: 5                # was notification_cooldown; v2 default is 0
    container_action_cooldown: 300     # was action_cooldown; v2 default is 60
    hide_full_regex: true              # was hide_regex_in_title
    regex_case_sensitive: false        # v2 default is true
    ignore_keywords:                   # was excluded_keywords
      - keyword: debug
    merge_matches: true                # v2 default is false; restores v1 behavior

  keywords:                            # was global_keywords.keywords
    - keyword: "critical"

containers:
  never_monitor:
    container_names: ["loggifly"]      # was settings.excluded_containers

  rules:
    - container_name: vaultwarden
      ntfy_tags: "closed_lock_with_key"
      ntfy_priority: 5
      ntfy_topic: security
      keywords:
        - regex: '(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Username or password is incorrect. Try again. IP: (?P<ip>\d{1,3}(?:\.\d{1,3}){3}). Username: (?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
          message_template: |
            Failed login!
            Email: '{{ email }}'
            IP Address: {{ ip }}
            Time: {{ timestamp }}
          title_template: "Failed Vaultwarden login"  # {variable} → {{ variable }}
          ntfy_tags: "rotating_light"
      container_events:
        - event: crash
          container_action: restart    # was action

  # groups of rules sharing the same scope, replaces the hosts: block
  groups:
    - scope:
        hosts: ["nas"]
      rules:
        - container_name: postgres
          keywords:
            - keyword: "FATAL"
            - keyword: "could not connect"
        - container_name: nginx
          keywords:
            - keyword: "upstream timed out"

swarm:                                 # was swarm_services
  rules:
    - service_name: app_worker
      keywords:
        - keyword: "timeout"
        - keyword: "connection refused"

notifications:
  ntfy:
    url: "http://ntfy.example.com"
    topic: "alerts"
```
:::