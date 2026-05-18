---
title: Containers Section
---

# Containers 

Here you can define containers and specify keywords, regex patterns and container events to monitor
You can also set optional settings on container and keyword/regex/event level.

The container names must match the exact container names you would get with `docker ps`.

## **Keywords**, **Regular Expressions** and **Keyword Groups**

Configure keywords, regex patterns and keyword groups that should be monitored for a container.

Keyword groups consist of a list of keywords that are treated as a group. A notification will be triggered when all of the keywords in the group are found in a log entry.


::: code-group

```yaml [Keywords]
containers:
  container1:
    keywords:
      - error               # simple keyword
      - keyword: critical   # another way to set a simple keyword
    
```

```yaml [Regex]
containers:
  container1:
    keywords:
      - regex: 'download.*failed'    # this is how to set regex patterns
```

```yaml [Keyword Groups]
containers:
  container4:
    keywords:
      - keyword_group:
        - error
        - critical
        - timeout
```

:::

## Monitor Container Events

With the `container_events` option you can monitor container events like start, stop, crash, etc.
Just like with keywords, you can set settings per container or per event.

```yaml
containers:
  container6:
    attach_logfile: true
    container_events:
      - event: crash
        title_template: '{container} crashed with exit code {exit_code}'
      - event: start
        attach_logfile: false
```

::: details Supported events
| Event | Triggered when... |
|-------|-------------|
| `start` | container is started |
| `stop` |  container is stopped via a stop request (does not trigger on crashes or forced exits)  |
| `die` | container exits, regardless of the reason (stop, crash, or kill)  |
| `crash` | container exits with an exit code ≠ 0 |
| `destroy` | container is removed |
| `healthy` | container health status changes to healthy |
| `unhealthy` | container health status changes to unhealthy |
| `starting` | container health status changes to starting |
| `oom` | container runs out of memory (OOM) |
| `kill` | container is killed by a signal |
| `create` | container is created |
| `restart` | container is restarted |
:::


## Settings per container and keyword

Most of the **settings** from the `settings` and the `notifications` sections can be set per container or per keyword/regex.<br>
A summary of all the settings and where you can set them can be found [here](../settings-overview.md).

::: info
When multiple keywords with the same setting (e.g., `title_template`) are found in a log line, the one listed first in the YAML takes precedence.
:::

Here are some examples:

::: details Attach Logfiles

With the `attach_logfile` option you can attach a logfile to the notification. 

```yaml
containers:
  container2:
  attach_logfile: true  # applies to all keywords in this container
  attachment_lines: 100  # applies to all keywords in this container
    - keyword: error
      attach_logfile: true  # applies to this keyword (overrides global setting)
      attachment_lines: 50  # applies to this keyword (overrides global setting)
```
:::

::: details Exclude Keywords

You can also exclude certain keywords from triggering notifications. This can be done globally (in [`settings`](./settings.md)), per container or per keyword/regex. 

```yaml
containers:
  container3:
    # Exclude keywords for a whole container
    excluded_keywords:
      - timeout  # This keyword will be ignored for this container
      - regex: \btimeout\b.*  # This regex will be ignored for this container
    keywords:
      - keyword: error
        # Exclude keywords for a specific keyword or regex pattern
        excluded_keywords:
          - timeout  # Log lines with 'error' will be ignored when 'timeout' is also found
```
:::

::: details Longer Example with settings on different levels
```yaml
containers:
  container5:
    apprise_url: "discord://webhook-url"  
    ntfy_tags: closed_lock_with_key   
    ntfy_priority: 3
    ntfy_topic: container3
    attachment_lines: 50
    title_template: '{keywords} found in {container}'
    notification_cooldown: 2  
    attach_logfile: true
    action_cooldown: 60 
  
    keywords:
      - critical

      - regex: 'download.*failed' 
        ntfy_tags: partying_face   
        ntfy_priority: 5
        ntfy_topic: error
        attachment_lines: 10

      - keyword: timeout
        apprise_url: "discord://webhook-url" 
        title_template: '{container} restarted because these keywords were found: {keywords}'
        notification_cooldown: 10
        attach_logfile: true


```
:::



## Keep it simple

If `global_keywords` are configured and you don't need additional keywords or settings for a container you can **leave it blank**:
  
```yaml
containers:
  container6:
  container7:
```

::: info
How to configure Container Actions is explained [here](../actions.md) and how to customize notifications with `title_template` and `message_template` is explained [here](../customize-notifications/).
:::
