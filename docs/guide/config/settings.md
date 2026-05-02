---
title: Settings
---

# Settings

`settings:` contains only **non-inheritable application settings**, things that control LoggiFly's own behavior rather than how notifications are configured.

```yaml
settings:
  log_level: INFO
  multi_line_entries: true
  reload_config: true
  system_notifications: true
  compact_summary_message: false
```

### Fields Reference

| Field | Default | Description |
|-------|---------|-------------|
| `log_level` | `INFO` | Log verbosity level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `multi_line_entries` | `true` | Catch log entries that span multiple lines instead of going line by line. |
| `reload_config` | `true` | Automatically reload the config when the `config.yaml` file is changed. |
| `system_notifications` | See Below | Control LoggiFly's own status notifications (startup, shutdown, config reload, monitor events). See below. |
| `compact_summary_message` | `false` | Format summary of monitored targets as comma-separated list instead of multi-line. |

### `system_notifications`

Controls whether LoggiFly sends notifications about its own operational events. Accepts either a single boolean (applies to all) or a sub-object for per-event control:

::: code-group
```yaml [Disable all]
settings:
  system_notifications: false
```
```yaml [Per-event control]
settings:
  system_notifications:
    start: true          # notification when LoggiFly starts
    shutdown: true       # notification when LoggiFly shuts down
    config_reload: false # suppress config reload notifications
    monitor_event: true  # notification when a container starts/stops being monitored
```
:::

All four events default to `true` when `system_notifications` is not set.
