---
title: Keywords & Triggers
---

# Keywords & Triggers

There are two types of triggers: `keywords` and `container_events`.


## Keyword Types

The `keywords` list accepts three types, which can be mixed freely:

::: code-group
```yaml [keyword]
keywords:
  - error           # simple keyword
  - keyword: failed login   # another way to set a simple keyword
```

```yaml [regex]
keywords:
  - regex: 'download.*failed'
  - regex: 'process (?P<pid>\d+) crashed'  # named capture group → available in templates
```


```yaml [all_of]
# these only trigger when all members of the all_of group match in the same log entry
keywords:
  - all_of:
      - error
      - timeout
      - keyword: database
  - all_of:
      - keyword: authentication
      - regex: 'failed.*attempt'
```
:::

::: info
- keywords are case-insensitive
- regexes are case-sensitive by default (controlled by `regex_case_sensitive` in [`defaults:`](./settings#defaults))
- named capturing groups (`(?P<name>...)`) can be used to extract values that become available as template variables in `title_template` and `message_template`. See [Customize Noticications](../customize-notifications/) and [Extract from Regex](../customize-notifications/regex).
:::

---

## Container Events

Monitor Docker container lifecycle events instead of (or in addition to) log content.

```yaml
containers:
  rules:
    - container_name: my-app
      container_events:
        - event: crash
        - event: oom
```

::: details Supported Events

| Event | Triggered when... |
|-------|-------------------|
| `start` | Container is started |
| `stop` | Container is stopped via a stop request (not on crashes or forced exits) |
| `die` | Container exits, regardless of reason (stop, crash, or kill) |
| `crash` | Container exits with a non-zero exit code |
| `destroy` | Container is removed |
| `healthy` | Container health status changes to healthy |
| `unhealthy` | Container health status changes to unhealthy |
| `starting` | Container health status changes to starting |
| `oom` | Container is killed by the OOM killer |
| `kill` | Container is killed by a signal |
| `create` | Container is created |
| `restart` | Container is restarted |
:::
---

## How triggers are merged across levels

Keywords and container events can be configured at the following levels:

- **Global level** (`global.keywords`): applied to every matched target across all sources.
- **Source level** (`containers.keywords`, `containers.container_events`): applied to every target of that source (`containers` or `swarm`) that is matched by any rule.
- **Rule level** (`rules[*].keywords`, `rules[*].container_events`): applied only to containers matched by that specific rule.

Triggers from all levels are **combined**. Source-level triggers come first, followed by rule-level triggers.<br>
If the same container event type appears at multiple levels, the **most specific level's** settings are used.

::: info
There will most likely be more log sources in the future. This is why there is **no** `global.container_events` section since that is specific to containers and swarm. 
:::

::: details Example

```yaml
global:
  keywords:
    - "critical" # applied to every matched target across all sources (containers and swarm)

containers:
  keywords:
    - keyword: "panic" # applied to every container matched by any rule

  container_events:
    - event: crash # applied to every container matched by any rule

  rules:
    - container_name: my-app
      keywords:
        - keyword: "error" # applied only to containers matched by this rule
      container_events:
        - event: start # applied only to containers matched by this rule

swarm:
  rules:
    - service_name: my-service
      keywords:
        - keyword: "timeout" # applied only to services matched by this rule
```
:::


## Threshold-Based Triggering with `trigger_on`

Instead of triggering on every match, `trigger_on` delays a trigger until the keyword has matched a minimum number of times within a sliding time window. This is useful for noisy signals where a single occurrence is not actionable, but repeated occurrences indicate a real problem.

`trigger_on` works on `keyword:`, `regex:`, and `all_of:` items, as well as on `container_events` items.

::: code-group
```yaml [keyword]
keywords:
  - keyword: "connection timeout"
    trigger_on:
      count: 5
      timeframe: 60
    title_template: "{{ container_name }}: {{ trigger_on_count }} timeouts in {{ trigger_on_timeframe }}s"
```

```yaml [container_event]
container_events:
  - event: crash
    trigger_on:
      count: 5
      timeframe: 60
    title_template: "{{ container_name }} crashed {{ trigger_on_count }} times in {{ trigger_on_timeframe }}s"
```
:::

**Behavior:**
- Each match is recorded in an in-memory sliding window.
- When the match count reaches `count` within `timeframe` seconds, the trigger fires and the counter **resets to zero**.
- `trigger_cooldown` still applies as a gate before a match is evaluated against `trigger_on`.
- `count` must be `≥ 2`. `timeframe` must be `≥ 1` second.

[**Template variables**](../customize-notifications/#template-fields-reference) available when `trigger_on` is set:
- <code v-pre>{{ trigger_on_count }}</code>: the configured count threshold
- <code v-pre>{{ trigger_on_timeframe }}</code>: the configured timeframe in seconds


## Actions

You can configure `container_action` and `olivetin_actions` on keywords and container events.<br>
See [Actions](../actions) for more details.


## Per-Keyword `defaults` Settings

Any field from [`global.defaults:`](./global#defaults) can be set on an individual trigger (keyword or container event). These override the inherited value for that specific trigger only.

::: details Per Trigger Settings Example
```yaml
global:
  defaults:
    ntfy_priority: 1
    attach_logfile: false

containers:
  rules:
    - container_name: my-app
      keywords:
        - keyword: error
          ntfy_priority: 5          # override priority for this keyword only
          attach_logfile: true
          trigger_cooldown: 60
          title_template: "Error in my-app"

        - regex: 'panic.*goroutine'
          ntfy_topic: "critical-alerts"
          container_action: restart  # see Actions guide

      container_events:
        - event: crash
          ntfy_priority: 5
          attach_logfile: true
          title_template: "Container {{ container_name }} crashed"
```
:::


## Additional explanation on some of the settings from `global.defaults:`


### `merge_matches`

Controls what happens when **multiple keywords match in the same log line**.

- **`merge_matches: false`** (default): each matching keyword fires its own independent notification with its own configuration. One log line can produce multiple notifications.
- **`merge_matches: true`**: all keywords matching the same log line that have `merge_matches: true` set (whether inherited or set on the keyword itself) are merged into one notification. Keywords that have `merge_matches: false` fire their own independent notification.

```yaml
defaults:
  merge_matches: true

containers:
  rules:
    - container_name: my-app
      keywords:
        - keyword: "error"
          merge_matches: false # this keyword will not be merged with other keywords
```

`merge_matches` can be set at `defaults:`, source-level `defaults:`, rule level, or per-keyword. Setting it on individual keywords makes those keywords opt-in or opt-out of merging while others remain independent.

### `ignore_keywords`

Keywords or regex patterns that suppress a trigger when found in the same log line.

::: details Can be set at multiple levels
```yaml
defaults:
  ignore_keywords:
    - regex: "debug.*message"
containers:
  rules:
    - container_name: my-app
      ignore_keywords:
        - keyword: "ignoreforthisrule"
      keywords:
        - keyword: "error"
          ignore_keywords:
            - regex: "ignoreforthiskeyword"
    
```
:::
`ignore_keywords` are **merged** across all levels.


### `disable_trigger_notifications`

Suppresses the notification when a trigger fires, while still executing any configured actions (container actions, OliveTin actions). Useful when you only want to trigger automation without notification noise.

```yaml
keywords:
  - keyword: "unhealthy"
    disable_trigger_notifications: true
    container_action: restart
```
  
