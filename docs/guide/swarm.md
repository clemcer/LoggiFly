---
title: Docker Swarm
---

# Docker Swarm

LoggiFly does not monitor Swarm services directly, since the Swarm API is limited. Instead, it monitors the individual containers that belong to a configured Swarm service by recognizing the service name from the Docker Swarm labels.

This means that for LoggiFly to reliably monitor swarm services it has to be deployed as a global service on every node in the swarm cluster.

If you want to get context in your notifications about which node the container that has triggered a notification is running on, you can set the `LOGGIFLY_MODE` environment variable to `swarm`.

The `config.yaml` can be passed to each worker via [Docker Configs](https://docs.docker.com/reference/cli/docker/config/) (_see example_).

The configuration stays the same except that you set `swarm_services` instead of `containers` or use the `SWARM_SERVICES` environment variable instead of `CONTAINERS`.

If normal `containers` are set instead of or additionally to `swarm_services` LoggiFly will also look for these containers on every node.

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
      # GLOBAL_KEYWORDS: keyword1,keyword2
      # GLOBAL_KEYWORDS_WITH_ATTACHMENT: keyword3
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
swarm_services:
  nginx:
    keywords:
      - error
      - regex: \timeout\b.* 
  redis:
    - keyword: critical
      attach_logfile: true
```

If both nginx and redis are part of the same compose stack named `my_service` you can configure that service name to monitor both:
```yaml
swarm_services:
  my_service: # includes my_service_nginx and my_service_redis
    keywords:
      - error
      - regex: \timeout\b.* 
```

The `swarm_services` configuration is identical to that of `containers`, so for all available configuration options, refer to the [Containers section](./config_sections/containers) or the [Settings Overview](./settings-overview). 


