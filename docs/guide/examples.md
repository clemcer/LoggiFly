---
title: Examples
---

# Examples 

## Config Example

Here is an example config with some real use cases. 
::: details Config Example with Use Cases

<<< @/configs/config_example.yaml{yaml}

:::

::: info
Feel free to contribute your use cases to [the file](https://github.com/clemcer/loggifly/blob/main/docs/configs/config_example.yaml).
:::

## Systemd Monitoring

You can monitor systemd services / journal logs with LoggiFly by setting up a fluentbit container.

With this compose file journal logs are directly streamed to the fluentbit container logs where LoggiFly can then monitor them.

### Fluentbit Compose File
```yaml
services:
  fluentbit:
    image: fluent/fluent-bit:latest
    container_name: fluentbit
    read_only: true
    volumes:
      - /var/log/journal:/var/log/journal:ro
    command: >
      /fluent-bit/bin/fluent-bit
      -i systemd -p tag=journal -p path=/var/log/journal -p read_from_tail=true
      -o stdout -p match=* -p format=json_lines
    restart: unless-stopped
```

### LoggiFly Config Example

```yaml
containers:
  fluentbit:
    keywords:
      - keyword_group: 
          - ssh
          - failed
          - password
        title_template: 'Failed SSH Login Attempt'
        message_template: '{MESSAGE}' # this is a field available in the JSON log entry
        notification_cooldown: 0
        ntfy_tag: rotating_light

```

### Result

![Failed SSH Login](/ssh-failed-login.png)








