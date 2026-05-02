---
title: Containers & Rules
outline: [2-4]
---

# Containers & Rules

The `containers:` section is a **source configuration object**, it defines which containers to monitor and how.<br>
If you want to jump directly to the important configuration, scroll down to the [Rules](#rules) section.

## Structure of `containers:`

```yaml
containers:
  scope: ...          # optional: restrict this entire block to specific hosts
  never_monitor: ...  # absolute exclusion list
  defaults: ...       # overrides global defaults: for all container targets
  keywords: [...]     # applied to every matched container
  container_events: [...] # applied to every matched container
  rules: [...]        # determine which containers to monitor
  groups: [...]       # advanced: groups of rules sharing common config
```
::: info  
The `swarm:` section has the same structure, see the [Swarm guide](../swarm) for swarm-specific details and deployment.
:::

## `never_monitor`

Containers matching `never_monitor` are **always skipped**, regardless of matching rules.

```yaml
containers:
  never_monitor:
    container_names:
      - socket-proxy
      - "*-backup"    # glob pattern: any container ending in -backup
```

Glob patterns are supported (see [Glob Patterns](#glob-patterns) below).

---

## `scope.hosts`

Restricts the **entire `containers:` block** to specific Docker hosts. If a container is running on a host not in this list, the whole `containers:` config does not apply to it.

```yaml
containers:
  scope:
    hosts: ["prod-host1", "prod-host2"]
```

Glob patterns are supported in host names. This is distinct from `never_monitor`, it's not an exclusion, it's a scope restriction. Containers on other hosts are simply not considered.

For per-rule host scoping (more granular), see [Rule-Level scope.hosts](#rule-level-scopehosts).

---

## `containers.defaults:`

Each source can have its own `defaults:` block that overrides the global `defaults:` for all targets under that source. Useful for setting different baselines for containers vs. Swarm services.

```yaml
defaults:
  trigger_cooldown: 0      # global baseline

containers:
  defaults:
    trigger_cooldown: 10   # applies to all container targets
    attach_logfile: true
```

See [Settings & Defaults](./settings-and-defaults#defaults) for all available fields.

---

## Source-level `keywords` and `container_events`

Keywords and container events placed directly under `containers:` (not inside a rule) are applied to **every container matched by any rule**. Source-level keywords are combined with global and rule-level keywords.

```yaml
containers:
  keywords:
    - keyword: "critical"    # monitored on every matched container
    - keyword: "out of memory"

  container_events:
    - event: crash           # monitored on every matched container
    - event: oom
```

See [Keywords & Triggers](./keywords-and-triggers) for full keyword and event configuration.

---

## Rules

Rules are the core of the config. A container is monitored if it matches **at least one enabled rule**. Rules carry the configuration (keywords, events, settings) that applies to matched containers.

One container can match multiple rules, see [Multi-Rule Merging](#multi-rule-merging) for more details.

### Basic Rule Structure

```yaml
containers:
  rules:
    - id: my-rule          # optional; auto-generated as "rule-1", "rule-2" if omitted
      enabled: true        # default true; set false to disable without removing
      scope: ...           # optionally restrict this rule to specific hosts
      match: ...           # this is where you define the matching criteria.
      keywords: []         # keywords and events for this rule
      container_events: [] # container events for this rule
      # any setting from defaults: can also be set here on rule level to override the global or source-level value for matched containers
```

### How you can match containers in a rule
 There are two options. Either the more complex but also more flexible `match:` block where you can combine multiple criteria with include and exclude lists, or the simpler `container_name:` shorthand for single-criterion matching. See [Shorthand Syntax](#shorthand-syntax) below.

::: code-group
```yaml [Full match block]
containers:
  rules:
    # full match block with include and exclude lists
    - match:
        include:
          container_names: ["web-*", "api-*"]
        exclude:
          container_names: ["*-test"]
      keywords:
        - keyword: "error"
```
```yaml [Shorthand syntax]  
containers:
  rules:
    # shorthand syntax for simple cases
    - container_name: nginx   # shorthand
      keywords:
        - keyword: error
    
    # equivalent to:
    # - match:
    #     include:
    #       container_names: ["nginx"]
    #   keywords:
    #     - keyword: error

```
:::

Using both a shorthand and a `match:` block in the same rule is a validation error.

### Glob Patterns

Just like hotnames in `scope.hosts`, container names also support Python `fnmatch`-style glob patterns:

| Pattern | Matches |
|---------|---------|
| `web-*` | any name starting with `web-` |
| `*-api` | any name ending with `-api` |
| `app-?` | `app-` followed by exactly one character |
| `[abc]-*` | any name starting with `a-`, `b-`, or `c-` |
| `*` | every container (matches everything) |

Matching is **case-sensitive**.

### Rule-Level `scope.hosts`

Each rule can independently restrict itself to specific hosts. This allows fine-grained multi-host configurations (different rules for different hosts) without separate config blocks.

::: details Example
```yaml
containers:
  rules:
    - id: db-only-on-dbhost
      scope:
        hosts: ["db-host"]        # only applies on db-host
      match:
        include:
          container_names: ["*postgres*"]
      keywords:
        - keyword: "deadlock"

    - id: all-hosts-web
      match:
        include:
          container_names: ["web-*"]
      keywords:
        - keyword: "error"
```
:::

Glob patterns are supported in `scope.hosts`. If `scope.hosts` is omitted on a rule, the rule applies to all hosts.

### Rule `id` and `enabled`

- **`id:`** Optional string identifier for the rule. If omitted, auto-generated as `rule-1`, `rule-2`, etc. IDs must be unique within the list.
- **`enabled:`** Defaults to `true`. Set to `false` to disable a rule without removing it from the config (useful for temporarily switching something off).

```yaml
containers:
  rules:
    - id: debug-rule
      enabled: false       # disabled, containers matched here won't be monitored
      container_name: noisy-app
      keywords:
        - keyword: error
```

### `defaults` fields {#defaults-fields}

Any field under [`defaults:`](./settings-and-defaults#defaults) can be set at rule level effectively overriding the value set under `defaults` or `containers.defaults`.

```yaml
defaults:
  trigger_cooldown: 0

containers:
  rules:
    - id: debug-rule
      container_name: my-app
      trigger_cooldown: 10 # overrides trigger_cooldown for containers matching this rule
      ntfy_topic: "my-app"
      ignore_keywords:
        - keyword: "debug"
      keywords:
        - keyword: "error"
```
### Detailled `rule` Example

::: details
```yaml
    # simple rule
    - container_name: my-app
      keywords:
        - keyword: "error"

    # full rule structure
    - id: my-rule          # optional; auto-generated as "rule-1", "rule-2" if omitted
      enabled: true        # default true; set false to disable without removing
      scope:
        hosts: ["host1"]   # optional; if omitted, applies to all hosts
      match:                # this is where you define the matching criteria.
        include:
          container_names: ["web-*", "api-*"]
        exclude:
          container_names: ["*-test"]
      keywords:
        - "critical" 
        - keyword: "error"
        - regex: "login.*failed"
      container_events:
        - event: crash
        - event: oom
      trigger_cooldown: 30  # any defaults field can be set at rule level
      attach_logfile: true
```
:::

### Multi-Rule Merging

When a container matches **multiple rules**, their configurations are merged in list order:

- **Triggers** (`keywords`, `container_events`): **merged** across all levels. Source-level keywords come first, then rule keywords in order.
- **Settings from [`defaults`](settings-and-defaults#defaults) fields** (e.g. `trigger_cooldown`, `attach_logfile`, `ntfy_priority`): see [Inheritance & Merging of Settings](../config/global#inheritance--merging-of-settings).

```yaml
global:
  keywords:
    - keyword: "critical"          # global-level: applied to every matched target across all sources (containers and swarm)
  defaults:
    ntfy_priority: 1

containers:
  keywords:
    - keyword: "warning"          # source-level: applies to every matched container

  rules:
    - container_name: "*"  # matches all containers
      trigger_cooldown: 10
      keywords:
        - keyword: "error"            # applies to all containers

    - container_name: web-app  # also matches web-app
      trigger_cooldown: 30             # last match → wins over 10
      keywords:
        - keyword: "timeout"
```

For `web-app` (matched by both rules), the effective config is:
- `ntfy_priority: 1` (global level)
- `trigger_cooldown: 30` (second rule wins)
- keywords: `warning`, `error`, `timeout`, `critical` (combined from all levels: source → rules → global)        
  
              
:::tip
Set the `DEBUG_TARGET_CONFIG` environment variable to `true` to log the full effective config for all monitored containers at startup. This is useful for verifying multi-rule merging is working as expected. Debug logging needs to be enabled as well.
:::

---

## Groups

Groups are an advanced feature for sharing common config across multiple rules. A group can hold the same fields as the `containers:` source block: `scope`, `never_monitor`, `defaults` fields, `keywords`, `container_events` plus a required `rules:` list. Every rule inside the group inherits the group's config as an additional baseline.

This is most useful when you have several containers that should share the same settings or scopes, for example containers on the same remote host that each need different keywords or settings, without repeating `scope.hosts` on every rule.

```yaml
containers:
  groups:
    - scope:
        hosts: ["my-remote-host"]
      trigger_cooldown: 30
      never_monitor:
        container_names: ["*-test"]
      keywords:
        - keyword: "connection refused"   # applied to every rule in this group

      rules:
        - container_name: my-app
          keywords:
            - keyword: error
        - container_name: my-other-app
          trigger_cooldown: 60            # overrides the group's 30
          keywords:
            - keyword: warning
```

### Inheritance chain with groups

Groups add one level between source defaults and rule config.
The same merging semantics as explained above apply throughout.

### What a group can hold

Basically everything that the [source configuration](#structure-of-containers) (`containers:` / `swarm`) can hold except for `groups` obiously since groups cannot be nested (`groups:` inside a group is not allowed)


```yaml
containers:
  groups:
    - scope: ...          # restrict this group to specific hosts
      never_monitor: ...  # exclusion list for this group only
      defaults: ...       # overrides global & source defaults for targets in ghis group
      keywords: [...]     # applied to every matched container from this group
      container_events: [...] # applied to every matched container from this group
      rules: [...]        # Required. At least one rule
```

### Flat rules and groups side by side

Flat `rules:` and `groups:` coexist under `containers:`. Flat rules are unaffected by groups and work exactly as before.

```yaml
containers:
  keywords:
    - keyword: critical             # applies to everything

  rules:
    - container_name: "*"           # normal rule
      keywords:
        - keyword: oom

  groups:
    - scope:
        hosts: ["prod-host"]        # restricts containers matched in this group to this host only
      ntfy_topic: "prod-alerts"
      rules:
        - container_name: "*-api"
          keywords:
            - keyword: error
        - container_name: "*-db"
          keywords:
            - keyword: deadlock
```

::: info
The `swarm:` section supports `groups:` with the same structure. Inside swarm groups, rules use `service_name:` / `stack_name:` shorthands or `match.include.service_names` / `match.include.stack_names`.
:::