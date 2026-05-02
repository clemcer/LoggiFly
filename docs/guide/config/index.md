---
title: Configuration Overview
---

# Configuration Overview

LoggiFly is configured via a `config.yaml` file mounted at `/config/config.yaml` (override with the `CONFIG_PATH` environment variable). Most settings can also be set via [environment variables](../environment-variables), but the config file is required for rules, per-target settings, and all advanced features.


## Log Sources

At the moment LoggiFly supports monitoring Docker containers and [Docker Swarm services](../swarm).<br>
These are referred to as **sources** throughout the documentation.<br>

The following walkthrough will mostly cover the `containers` source, but the same principles usually apply to the `swarm` source as well. For more details and the differences between the two, refer to the [Swarm](../swarm) guide.

## Top-Level Keys in config.yaml
```yaml
version: 2
global:
containers:
swarm:
notifications:
settings:
```

## Table of Contents

**Configuration Walkthrough:**
- [Settings](settings): covers application settings under `settings:`
- [Global](global): covers global keywords and global defaults under `global:`
- [Notifications](notifications): covers notification settings under `notifications:`
- [Containers & Rules](containers-and-rules): covers source configuration options and rules under `containers:`
- [Keywords & Triggers](keywords-and-triggers): covers the configuration of triggers like `keywords:` and `container_events:`

**Reference:**
- [Config Schema](config/schema): dynamically generated schema reference of the whole config
- [Environment Variables](environment-variables): environment variables that can be used instead of or in addition to the config file
- [Configuration via Labels](label-config): how to configure LoggiFly via Docker labels
- [Swarm](swarm): covers `swarm:` specific differences from `containers:` section


## Full Config Reference



::: details Full Config Reference (every option with comments)

<<< @/configs/config_reference.yaml{yaml}

:::

::: tip
For an example with real use cases, take a look at this **[config example](../examples#config-example)**.
:::
