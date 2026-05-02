---
title: Template Fields Reference
---

# Template Fields Reference

You can customize the message and title of your notifications using `message_template` and `title_template`.

Templates use [Jinja2](https://jinja.palletsprojects.com/) syntax. Variables are wrapped in double curly braces: <code v-pre>{{ container_name }}</code>. Beyond simple variable substitution, Jinja2 gives you conditionals, filters, and default values (covered [below](#jinja2-features)).

You can use [default template fields](#always-available-template-fields) or extract [additional information](#additional-fields) from logs using JSON or regex.

::: details Both settings can be defined at the defaults, source or keyword level.
```yaml
defaults:
  title_template: "{{ keywords }} found in {{ container_name }}"
  message_template: |
    Time: {{ datetime }}
    Log: {{ log_entry }}

containers:
  rules:
    - container_name: container1
      title_template: "{{ container_name }}: {{ keywords }}"
      message_template: "{{ log_entry }}"
      keywords:
        - keyword: "error"
          title_template: "Error found in container1 at {{ datetime }}"
          message_template: |
            Found keywords: {{ keywords }}
            Time: {{ datetime }}
            Log: {{ log_entry }}
```
:::


Here are some example notifications using templates:
![Notifications with templates](/template_collage.png)


::: warning
Using templates can lead to you **not getting all information** that would otherwise be included in the notifications by default.

Two examples are the `host_identifier` (for swarm or multi-host setups) and the `action_result_message` of **container actions**.

This info is included in the notification title by default, but if you use a `title_template` it is up to you to include it. You can use `{% if %}` to only show these fields when they are actually present, see [below](#conditionals).
:::

## Always Available Template Fields

The following template fields are always available for both `message_template` and `title_template`, although they might be empty if no information is available.

::: details Default Template Fields

| Field | Description |
|-------|-------------|
| <code v-pre>{{ notification_type }}</code> | Type of notification (either `log_match` or `docker_event`) |
| <code v-pre>{{ monitor_type }}</code> | Either `container` or `swarm` depending on whether the monitored target is a regular container or a swarm service |

### Log Match Information

| Field | Description |
|-------|-------------|
| <code v-pre>{{ keywords }}</code> | Matched keywords (formatted list) |
| <code v-pre>{{ keyword }}</code> | Alias for `keywords` |
| <code v-pre>{{ log_entry }}</code> | Full log entry |

### Threshold Triggering Information

Only present when [`trigger_on`](../config/keywords#trigger-on) is configured on the matched keyword.

| Field | Description |
|-------|-------------|
| <code v-pre>{{ trigger_on_count }}</code> | The configured match count threshold |
| <code v-pre>{{ trigger_on_timeframe }}</code> | The configured timeframe in seconds |

### Container Action Information

Only present when a [container action](../actions#container-actions) is triggered.

| Field | Description |
|-------|-------------|
| <code v-pre>{{ container_action_result_message }}</code> | Result message of the triggered [container action](../actions#container-actions) |
| <code v-pre>{{ container_action_succeeded }}</code> | `True` if the container action succeeded, `False` otherwise |
| <code v-pre>{{ container_action_type }}</code> | Type of the triggered action (e.g. `restart` or `stop`) |
| <code v-pre>{{ container_action_target }}</code> | Target container of the action |
| <code v-pre>{{ container_action_string }}</code> | Full configured action string (e.g. `restart@container_name`) |

### Container Information

| Field | Description |
|-------|-------------|
| <code v-pre>{{ container_id }}</code> | Container ID (12 characters) |
| <code v-pre>{{ full_container_id }}</code> | Full container ID (64 characters) |
| <code v-pre>{{ container_name }}</code> | Container name |
| <code v-pre>{{ docker_image }}</code> | Container image name |
| <code v-pre>{{ target_name }}</code> | `container_name` for regular containers, or service name with replica number for swarm containers |
| <code v-pre>{{ service_name }}</code> | Swarm service name (if applicable) |
| <code v-pre>{{ stack_name }}</code> | Docker stack name (if applicable) |

### Docker Container Event Information

Only available for notifications triggered by [container events](../config/containers#monitor-container-events).

| Field | Description |
|-------|-------------|
| <code v-pre>{{ event }}</code> | Docker event type (e.g., `start`, `stop`, `die`) |
| <code v-pre>{{ exit_code }}</code> | Container exit code (for `die` events) |
| <code v-pre>{{ signal }}</code> | Signal that stopped the container (if applicable) |

### Host Information

| Field | Description |
|-------|-------------|
| <code v-pre>{{ hostname }}</code> | Host machine name or [label](../remote-hosts#labels) if set |
| <code v-pre>{{ host_identifier }}</code> | Hostname for multi-host setups; `manager@node1` / `worker@node2` for swarm, otherwise empty |

### Time Information

| Field | Description |
|-------|-------------|
| <code v-pre>{{ timestamp }}</code> | ISO format timestamp (YYYY-MM-DDTHH:MM:SSZ) |
| <code v-pre>{{ date }}</code> | Date only (YYYY-MM-DD) |
| <code v-pre>{{ time }}</code> | Time only (HH:MM:SS) |
| <code v-pre>{{ datetime }}</code> | Combined date and time (YYYY-MM-DD HH:MM:SS) |
:::


## Additional Fields

Beyond the default fields, you can extract additional information from logs:
- **JSON logs**: All JSON keys become available as template fields → [Learn more](./json)
- **Plain text logs**: Use regex named capturing groups to extract fields → [Learn more](./regex)

::: info **Field Precedence**
When the same field name exists in multiple sources, the following precedence is applied:

**Fields from JSON logs** > **Fields from regex** > **Default fields**
:::

## Jinja2 Features

Because templates use Jinja2, you have more than just variable substitution available.

### Conditionals

Use `{% if %}` to only include parts of a template when a field is present. This is useful for optional fields like those with info regarding container actions:

```jinja
{% if container_action_result_message %}
Action result: {{ container_action_result_message }}
{% endif %}
```
or something more complex:

```jinja
{% if container_action_succeeded is none %}
  No container action configured for {{ container_name }}
{% elif container_action_succeeded %}
  Succecssfully performed action '{{ container_action_type }}' on {{ container_name }}
{% else %}
  Action '{{ container_action_type }}' on {{ container_name }} failed!
{% endif %}
```



### Default Values

Use the `default` filter to provide a fallback when a field is empty:

```jinja
{{ host_identifier | default("local") }}
```

### Filters

Jinja2 filters transform a value inline using the `|` pipe syntax:

| Syntax | Description |
|--------|-------------|
| <code v-pre>{{ container_name \| upper }}</code> | formats the container name in uppercase (`NGINX`) |
| <code v-pre>{{ keywords \| lower }}</code> | formats keywords in lowercase |
| <code v-pre>{{ log_entry \| truncate(100) }}</code> | trims long log lines to 100 characters |

A few commonly useful filters: `upper`, `lower`, `truncate(n)`, `trim`, `replace("old", "new")`.

For the full filter reference see the [Jinja2 docs](https://jinja.palletsprojects.com/en/stable/templates/#filters).

::: info
When you reference a template field that does not exist, the notification is still sent. The missing field is left blank and a warning is logged.
:::

## Examples

### Basic Message Template

```yaml
containers:
  rules:
    - container_name: nginx
      keywords:
        - keyword: error
          title_template: "🚨 Error in {{ container_name }}"
          message_template: |
            Log: {{ log_entry }}
            Time: {{ datetime }}
```

### Using Event Fields for Container Events

```yaml
containers:
  rules:
    - container_name: app
      container_events:
        - event: crash
          title_template: "Container {{ target_name }} crashed"
          message_template: |
            Exit code: {{ exit_code }}
            Image: {{ docker_image }}
            Time: {{ datetime }}
```

### Conditional Host Identifier

```yaml
defaults:
  title_template: "{% if host_identifier %}[{{ host_identifier }}] {% endif %}{{ container_name }}: {{ keywords }}"
```

### Threshold Trigger Summary

```yaml
keywords:
  - keyword: "connection timeout"
    trigger_on:
      count: 5
      timeframe: 60
    title_template: "{{ trigger_on_count }} timeouts in {{ trigger_on_timeframe }}s — {{ container_name }}"
```