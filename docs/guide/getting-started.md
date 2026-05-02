---
title: What is LoggiFly?
---

# Getting Started

The quickest way to get started is by configuring LoggiFly with environment variables only, but for full flexibility and feature access, using a `config.yaml` file is recommended.


The following section will provide a quick start with minimal configuration. 
For more features and customization options, start [here](./config/) to learn more about how to configure LoggiFly.

## Notification Services

You can directly send notifications to ntfy and change topic, tags, priority, etc. 

You can also send notifications to most other notification services via **Apprise**. Just follow their [docs](https://github.com/caronc/apprise/wiki) on how to best configure the Apprise URL for your notification service.


## Configuration

The following docker compose examples presume that you are using a `config.yaml` file. If don't want to use a config file, you can comment out the `config.yaml` mount and use environment variables only.

::: info
Environment variables allow for a simple and much quicker setup but they don't support configuring different keywords per container or features like regex, container actions, message formatting and more.
With a `config.yaml` file you have access to all features and can apply settings at multiple levels: globally, per log source, per rule and per trigger, allowing for much more fine-grained control.
:::

#### Environment Variables
Here are some environment variables to give you a quick start without having to create a `config.yaml` file.
Just edit and paste them into the `environment` section of your docker compose file.

::: details Environment Variables
```yaml
    environment:
      # Choose at least one notification service
      NTFY_URL: "https://ntfy.sh"
      NTFY_TOPIC: "your_topic"
      # ntfy token or username + password for authentication
      NTFY_TOKEN: <token>
      NTFY_USERNAME: <username>
      NTFY_PASSWORD: <password>
      APPRISE_URL: "discord://..."        # Apprise-compatible URL

      CONTAINERS: "vaultwarden,audiobookshelf"   # comma-separated container names to monitor
      GLOBAL_KEYWORDS: "error,failed login"  # keywords applied to all monitored containers
```
:::

#### config.yaml

::: info Tips
- For all configuration options take a look at the [Configuration Walkthrough](./config/). 
- You can also draw inspiration from this **[config example](./examples#)** with some real use cases.
:::

Here is a very **minimal config** that you can edit and paste into a newly created `config.yaml` file in the mounted `/config` directory:

::: details config.yaml

<<< @/configs/minimal_config.yaml{yaml}


:::

## Docker Compose

For better security, it is best practice to use a Docker Socket Proxy when exposing the docker socket to an application. 
Below are some compose examples with two different socket proxies.

If you don't want to use a socket proxy, maybe because you want to use the [container actions](./actions#container-actions) feature, you can also just use the provided compose file with direct docker socket access.

::: code-group

<<< @/compose/compose.yaml{yaml} [docker socket access]

<<< @/compose/compose.tecnativa-proxy.yaml{yaml} [tecnativa/docker-socket-proxy]

<<< @/compose/compose.11notes-proxy.yaml{yaml} [11notes/socket-proxy]



:::

## Strict Config Validation

By default, unknown or misspelled field names in your `config.yaml` will cause LoggiFly to **refuse to start** with a validation error. This is to ensure no configuration of yours gets ignored without you noticing.

If this bothers you, you can set `STRICT_CONFIG=false` in your compose file to ignore invalid fields (for the most part) and only log a warning:

```yaml
environment:
  STRICT_CONFIG: "false"
```
