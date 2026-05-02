---
title: Docker Swarm
---

# Docker Swarm

LoggiFly does not monitor Swarm services directly, since the Swarm API is limited. Instead, it monitors the individual containers that belong to a configured Swarm service by recognizing the service name from the Docker Swarm labels.

This means that for LoggiFly to reliably monitor swarm services it has to be deployed as a global service on every node in the swarm cluster.

If you want to get context in your notifications about which node the container that has triggered a notification is running on, you can set the `LOGGIFLY_MODE` environment variable to `swarm`.

The `config.yaml` can be passed to each worker via [Docker Configs](https://docs.docker.com/reference/cli/docker/config/) (_see example_).

The configuration stays the same except that you set `swarm_services` instead of `containers` or use the `SWARM_SERVICES` environment variable instead of `CONTAINERS`.


## Docker Compose

```yaml
version: "3.8"

services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    deploy:
      mode: global  # runs on every node
      restart_policy:
        condition: any
        delay: 5s
        max_attempts: 5
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro 
    environment:
      TZ: Europe/Berlin
      LOGGIFLY_MODE: swarm
      # You can use environment variables instead of a config.yaml if you want
      # SWARM_SERVICES: nginx,redis
      # SWARM_STACKS: my_stack1,my_stack2
      # GLOBAL_KEYWORDS: keyword1,keyword2
      # For more environment variables see the environment variables section in the docs 
# Comment out the rest of this file if you are only using environment variables
    configs:
      - source: loggifly-config
        target: /config/config.yaml  

configs:
  loggifly-config:
    file: ./config.yaml  # SET THE PATH TO YOUR CONFIG.YAML HERE

```

## Configuring the `config.yaml`


In the `config.yaml`, you can configure Swarm services to be monitored in the same way as containers.

```yaml
swarm:
  rules:
    - service_name: nginx
      keywords:
        - error
        - regex: \timeout\b.*

    # you can also use the full match syntax
    - match:
        include:
          service_names: ["redis"]
      keywords:
        - keyword: critical
        - attach_logfile: true

    # or select a whole stack and use glob patterns
    - stack_name: my_stack*
      keywords:
        - keyword: critical
        - regex: \timeout\b.*
```

::: tip
Except for the matching syntax, the rule configuration options for `swarm_services` are identical to that of `containers`, so for all available configuration options, refer to the [Containers & Rules](./config/containers-and-rules) section. You can also refer to the [Config Reference](./config/index.md#full-config-example) for a full `config.yaml` reference or the [Config Schema](./schema/) for the dynamically generated schema reference of the whole config.
:::

