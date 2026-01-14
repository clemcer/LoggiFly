---
title: What is LoggiFly?
---

# Getting Started

LoggiFly can easily be deployed on Docker, Docker Swarm or Podman.<br>
The quickest way to get started is by configuring LoggiFly with environment variables only, but for full flexibility and feature access, using a `config.yaml` file is recommended.


The following section will provide a quick start with minimal configuration. 
For more features and customization options, start [here](./config_sections/) to learn more about how to configure LoggiFly.

## Notification Services

You can directly send notifications to ntfy and change topic, tags, priority, etc. 

You can also send notifications to most other notification services via **Apprise**. Just follow their [docs](https://github.com/caronc/apprise/wiki) on how to best configure the Apprise URL for your notification service.


## Configuration

The following docker compose examples presume that you are using a `config.yaml` file. If don't want to use a config file, you can comment out the `config.yaml` mount and use environment variables only.

::: info
Environment variables allow for a simple and much quicker setup but they don't support configuring different keywords per container or features like regex, container actions, message formatting and more.
With a `config.yaml` file you do have access to all features and are able to apply settings on three different levels: global, container and keyword, allowing for much more finegrained control.
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
      # ntfy Token or Username + Password In case you need authentication
      NTFY_TOKEN: <token>
      NTFY_USERNAME: <username>
      NTFY_PASSWORD: <password>
      APPRISE_URL: "discord://..."      # Apprise-compatible URL
    
      CONTAINERS: "vaultwarden,audiobookshelf"        # Comma-separated list
      GLOBAL_KEYWORDS: "error,failed login,password"  # Basic keyword monitoring
      GLOBAL_KEYWORDS_WITH_ATTACHMENT: "critical"     # Attaches a log file to the notification
```
:::

#### config.yaml

::: info Tips
- For all configuration options take a look at the [Config Walkthrough](./config_sections/). 
- If `/config` is mounted in your compose file, a **[template file](./config_sections/#config-template) will be downloaded** into that directory. You can edit the downloaded template file and rename it to `config.yaml` to use it. 
- You can also draw inspiration from this **[config example](./examples#)** with some real use cases.
:::

Here is a very **minimal config** that you can edit and paste into a newly created `config.yaml` file in the mounted `/config` directory:

::: details config.yaml


```yaml
# You have to configure at least one container.
containers:
  container-name:  # Exact container name
    keywords:
      - error
      - regex: (username|password).*incorrect 
  another-container:
    keywords:
      - login
    
# Optional. These keywords are being monitored for all configured containers. 
global_keywords:
  keywords:
    - failed
    - critical

notifications:     
  # Configure either ntfy or Apprise or both
  ntfy:
    url: http://your-ntfy-server  
    topic: loggifly                   
    token: ntfy-token               # ntfy token in case you need authentication 
    username: john                  # ntfy Username + Password in case you need authentication 
    password: 1234                  # ntfy Username + Password in case you need authentication 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```

:::





## Docker Compose

It is recommended to use a Docker Socket Proxy for better security. There are two examples for different socket proxies in case you are having issues with one of them.

If you don't want to use a socket proxy, maybe because you want to use the [`actions`](./actions#container-actions) feature, you can also just use the provided compose file with direct docker socket access.

::: code-group

```yaml [11notes/socket-proxy]
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly
    # It is recommended to set the user so that the container does not run as root
    user: 1000:1000
    read_only: true
    volumes:
      - socket-proxy:/var/run
      # Place your config.yaml here if you are using one
      - ./loggifly/config.yaml:/app/config.yaml
    depends_on:
      - socket-proxy
    restart: unless-stopped 

  socket-proxy:
    image: "11notes/socket-proxy:2"
    read_only: true
    # Make sure to use the same UID/GID as the owner of your docker socket. 
    # You can check with: `ls -n /var/run/docker.sock`
    user: "0:996"
    volumes:
      - "/run/docker.sock:/run/docker.sock:ro"
      - "socket-proxy:/run/proxy"
    restart: "always"

volumes: 
  socket-proxy:

```


```yaml [tecnativa/docker-socket-proxy]
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly 
    # It is recommended to set the user so that the container does not run as root
    user: 1000:1000
    read_only: true
    volumes:
     # Place your config.yaml here if you are using one
      - ./loggifly/config:/config
    environment:
      TZ: Europe/Berlin
      DOCKER_HOST: tcp://socket-proxy:2375
    depends_on:
      - socket-proxy
    restart: unless-stopped

  socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: docker-socket-proxy
    environment:
      - CONTAINERS=1  
      - POST=0       
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro  
    restart: unless-stopped
```


```yaml [docker socket access]
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly
    # It is recommended to run the container as the same UID/GID as the owner of your docker socket to avoid running as root.
    # But you can also just comment out the user line and run as root.
    # You can check the socket permissions with `ls -n /var/run/docker.sock`
    user: "0:996"
    read_only: true
    environment:
      TZ: Europe/Berlin
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./loggifly/config:/config    # Place your config.yaml in this directory
    restart: unless-stopped 
```
:::




