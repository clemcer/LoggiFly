---
title: Template Fields Reference
---

# Template Fields Reference

You can customize both the message and title of your notifications using `message_template` and `title_template`.

With template fields like `{container_name}` you can dynamically include information in the notification.

You can use [default template fields](#always-available-template-fields) or extract [additional information](#additional-fields) from logs using JSON or regex.

::: details Both settings can be defined at the global, container or trigger level.
```yaml
settings:
  title_template: "{keywords} found in {container_name}"
  message_template: |
    Time: {datetime}
    Log: {log_entry}

containers:
  container1:
    title_template: "{container_name}: {keywords}"
    message_template: "{log_entry}"
    keywords:
      - keyword: "error"
        title_template: "Error found in container1 at {datetime}"
        message_template: |
          Found keywords: {keywords}
          Time: {datetime}
          Log: {log_entry}
```
:::


Here are some example notifications using templates:
![Notifications with templates](/template_collage.png)




::: warning
Using templates can lead to you **not getting all information** that would otherwise be included in the notifications by default.

Two examples are the `host_identifier` (for swarm or multi-host setups) and the `action_result_message` of **container actions**.

This info is included in the notification title by default, but if if you use a `title_template` it is up to you 
to include it in the notification by using the template fields `{host_identifier}` and `{action_result_message}`.
:::

## Always Available Template Fields

The following template fields are always available for both `message_template` and `title_template` although they might be empty if no information is available.

::: details Default Template Fields

| Field | Description |
|-------|-------------|
| `{notification_type}` | Type of notification (either `log_match` or `docker_event`) |
| `{monitor_type}` | Either `container` or `swarm` depending on whether the monitored container is a regular container or belongs to a swarm service |

### Log match Information

| Field | Description |
|-------|-------------|
| `{keywords}` | Matched keywords (formatted list) |
| `{keyword}` | Alias for keywords |
| `{log_entry}` | Full log entry |

### Container Action Information

Only present when a [container action](../actions#container-actions) is triggered.

| Field | Description |
|-------|-------------|
| `{action_result_message}` | Result message of a triggered [container action](../actions#container-actions) |
| `{action_success}` | True if the triggered [container action](../actions#container-actions) was successful, False otherwise |
| `{action_type}` | Type of the triggered [container action](../actions#container-actions) (e.g. "restart" or "stop") |
| `{action_target}` | Target of the triggered [container action](../actions#container-actions) |
| `{action_string}` | Full configured action string of the triggered [container action](../actions#container-actions) (e.g. "restart@container_name") |

### Container Information

| Field | Description |
|-------|-------------|
| `{container_id}` | container ID (12 characters long) | 
| `{full_container_id}` | full container ID (64 characters long) |
| `{container_name}` | Container name |
| `{docker_image}` | Container image name |
| `{target_name}` | `container_name` for regular containers or service name with replica number for containers belonging to a swarm service |
| `{service_name}` | Swarm service name (if applicable) |
| `{stack_name}` | Docker stack name (if applicable) |

### Docker Container Event Information

Only available for notifications triggered by [container events](../config_sections/containers#monitor-container-events).

| Field | Description |
|-------|-------------|
| `{event}` | Docker event type (e.g., start, stop, die) |
| `{exit_code}` | Container exit code (for die events) |
| `{signal}` | Signal that stopped the container (if applicable) |

### Host Information

| Field | Description |
|-------|-------------|
| `{hostname}` | Host machine name or [label](../remote-hosts#labels) if set|
| `{host_identifier}` | hostname for multi-host setups, "manager@node1" or "worker@node2" for swarm if `LOGGIFLY_MODE=swarm`, otherwise None |


### Time Information

| Field | Description |
|-------|-------------|
| `{timestamp}` | ISO format timestamp (YYYY-MM-DDTHH:MM:SSZ) |
| `{date}` | Date only (YYYY-MM-DD) |
| `{time}` | Time only (HH:MM:SS) |
| `{datetime}` | Combined date and time (YYYY-MM-DD HH:MM:SS) |
:::


## Additional Fields

Beyond the default fields, you can extract additional information from logs:
- **JSON logs**: All JSON keys become available as template fields → [Learn more](./json)
- **Plain text logs**: Use regex named capturing groups to extract fields → [Learn more](./regex)

::: info **Field Precedence**
When the same field name exists in multiple sources, the following precedence is applied:

**Fields from JSON logs** > **Fields from regex** > **Default fields**
:::

## Examples using default template fields 

### Basic Message Template

```yaml
containers:
  nginx:
    keywords:
      - keyword: error
        title_template: "🚨 Error detected in {container_name}"
        message_template: |
          Log: {original_log_line}
          Time: {datetime}
```
### Using Event Fields for Container Events

```yaml
containers:
  app:
    container_events:
      - event: crash
        title_template: "Container {target_name} crashed"
        message_template: |
          Exit code: {exit_code}
          Image: {docker_image}
          Time: {datetime}
```

::: info
When you use a template field that does not exist the notification will still be sent. The template field will simply not be filled in the notification and a warning is logged.
:::