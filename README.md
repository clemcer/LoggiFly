<a name="readme-top"></a>

<div align="center">
  <a href="clemcer/loggifly">
    <img src="/images/icon.png" alt="Logo" width="200" height="auto">
  </a>
</div>
<h1 align="center">LoggiFly</h1>

  <p align="center">
    <a href="https://github.com/clemcer/loggifly/issues">Report Bug</a>
    <a href="https://github.com/clemcer/loggifly/issues">Request Feature</a>
  </p>

<br>

**LoggiFly** - A Lightweight Tool that monitors Docker Container Logs for predefined keywords 🔑 or regex patterns 🔍 and sends Notifications.<br>
Never miss critical container events again - Get instant alerts for security breaches, system errors, or custom patterns through your favorite notification channels. 🚀

**Ideal For**:
- ✅ Catching security breaches (e.g., failed logins in Vaultwarden)
- ✅ Debugging crashes with attached log context
- ✅ Monitoring custom app behaviors (e.g., when a user downloads an audiobook on your Audiobookshelf server)


<div align="center">
   <img src="/images/vault_failed_login.gif" alt="Failed Vaultwarden Login" width="auto" height="150">
</div>

---

## Content

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Quick Start](#️-quick-start)
- [Configuration Deep Dive](#-Configuration-Deep-Dive)
  - [Basic config structure](#-basic-structure)
  - [Environment Variables](#-enviroment-variables)
- [Tips](#-tips)

---

## 🚀 Features

- **🔍 Plain Text, Regex & Multi-Line Log Detection**: Catch simple keywords or complex patterns in log entries that span multiple lines.
- **🚨 Ntfy/Apprise Alerts**: Send notifications directly to Ntfy or via Apprise to 100+ different services (Slack, Discord, Telegram).
- **🐳 Fine-Grained Control**: Unique keywords and other settings (like ntfy topic/tags/priority) per container.
- **📁 Log Attachments**: Automatically include a log file to the notification for context.
- **⚡ Auto-Restart on Config Change**: The program restarts when it detects that the config file has been changed.

---
## 🖼 Screenshots

<div align="center">
   <img src="/images/abs_login.png" alt="Audiobookshelf Login" width="300" height="auto">
   <img src="/images/vault_failed_login.png" alt="Vaultwarden Login" width="300" height="auto">
   <img src="/images/abs_download.png" alt="Audiobookshelf Download" width="300" height="auto">
  <img src="/images/ebook2audiobook.png" alt="Ebook2Audiobook conversion finished" width="300" height="auto">

</div>

---

## ⚡️ Quick start


In this quickstart only the most essential settigs are covered, [here](#-Configuration-Deep-Dive) is a more detailed config walkthrough.<br>

Choose your preferred setup method - simple environment variables for basic use, or a YAML config for advanced control.
- Environment variables allow for a simple setup and let you spin this thing up in a minute
- With YAML you can use complex Regex patterns and have different keywords & other settings per container. 

<details><summary><em>Click to expand:</em> 🐋 <strong>Basic Setup: Docker Compose (Environment Variables)</strong></summary>
Ideal for quick setup with minimal configuration

```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly
    volumes:
#      - ./config.yaml:/app/config.yaml  # Path to your config file (ignore if you are only using environment variables)
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375
      # Choose at least one notification service
      NTFY_URL: "https://ntfy.sh"       # or your self-hosted instance
      NTFY_TOPIC: "your_topic"          # e.g., "docker_alerts"
      # Token or Username+Password In case you need authentication
      # NTFY_TOKEN:
      # NTFY_USERNAME:
      # NTFY_PASSWORD:
      APPRISE_URL: "discord://..."      # Apprise-compatible URL
    
      CONTAINERS: "vaultwarden,audiobookshelf"        # Comma-separated list
      GLOBAL_KEYWORDS: "error,failed login,password"  # Basic keyword monitoring
      GLOBAL_KEYWORDS_WITH_ATTACHMENT: "critical"     # Attaches a log file to the notification
  socket-proxy:
    image: lscr.io/linuxserver/socket-proxy
    environment:
      - CONTAINERS=1
      - POST=0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /run
    restart: unless-stopped 
```
</details>


<details><summary><em>Click to expand:</em><strong> 📜 Advanced Setup: YAML Configuration</strong></summary>

Recommended for granular control and regex patterns. <br>

**Step 1: Update Docker Compose**

Uncomment/add this line in your docker-compose.yml:
```yaml
volumes:
  - ./YOUR/CONFIG/FOLDER/config.yaml:/app/config.yaml  # 👈 Replace left side of the mapping with your local path
```
**Step 2: Create Config File**

Create the config.yaml in your chosen folder:
```bash
mkdir -p ./loggifly_config  # Example folder
cd ./loggifly_config
touch config.yaml           # Create empty file
```
**Step 3: Configure Your config.yaml**

Add this minimal example config to the file you just created and edit it according to your needs.<br>(If you want more options take a look at the more detailed [config walkthrough](#-Configuration-Deep-Dive) or at this [example config](/config.yaml)):
```yaml
# You have to configure at least one container.
containers:
  container-name:  # Exact container name
  # You don't have to use both `keywords` and `keyword_with_attachment`. One is enough
    keywords:
      - error
      - regex: (username|password).*incorrect  # Use regex patterns when you need them
    # Attach a log file to the notification 
    keywords_with_attachment:
      - warn

# Optional. These keywords are being monitored for all configured containers
global_keywords:
  keywords:
    - failed
  keywords_with_attachment:
    - critical

notifications:     
  # Configure either Ntfy or Apprise or both
  ntfy:
    url: http://your-ntfy-server  
    topic: loggifly                   
    token: ntfy-token               # Ntfy token in case you need authentication 
    username: john                  # Ntfy Username+Password in case you need authentication 
    password: 1234                  # Ntfy Username+Password in case you need authentication 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```
</details><br>


**When everything is configured start the container**


```bash
docker compose up -d
```

---


## 🤿 Configuration Deep Dive


The Quick Start only covered the essential settings, here is a more detailed walktrough of all the configuration options.


### 📁 Basic Structure

The **`config.yaml`** file is divided into four main sections:

1. **`settings`**: Global settings like cooldowns and log levels. (_Optional since they all have default values_)
2. **`notifications`**: Configure Ntfy (_URL, Topic, Token, Priority and Tags_) and/or your Apprise URL
3. **`containers`**: Define which Containers to monitor and their specific Keywords (_plus optional settings_).
4. **`global_keywords`**: Keywords that apply to _all_ monitored Containers.

<details><summary><em>Click to expand:</em><strong> ⚙️ Settings </strong></summary>

```yaml
# These are the default settings
settings:          
  log_level: INFO               # DEBUG, INFO, WARNING, ERROR
  notification_cooldown: 5      # Seconds between alerts for same keyword (per container)
  attachment_lines: 20          # Number of Lines to include in log attachments
  multi_line_entries: true      # Monitor and catch multi-line log entries instead of going line by line. 
  disable_restart: false        # Disable restart when a config change is detected 
  disable_start_message: false  # Suppress startup notification
  disable_shutdown_message: false  # Suppress shutdown notification
  disable_restart_message: false   # Suppress config reload notification
```

</details>



<details><summary><em>Click to expand:</em><strong> 📭 notifications </strong></summary>

```yaml
notifications:                       
  # At least one of the two (Ntfy/Apprise) is required.
  ntfy:
    url: http://your-ntfy-server    # Required. The URL of your Ntfy instance
    topic: loggifly.                # Required. the topic for Ntfy
    token: ntfy-token               # Ntfy token in case you need authentication 
    username: john                  # Ntfy Username+Password in case you need authentication 
    password: 1234                  # Ntfy Username+Password in case you need authentication 
    priority: 3                     # Ntfy priority (1-5)
    tags: kite,mag                  # Ntfy tags/emojis 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```
</details>


<details><summary><em>Click to expand:</em><strong> 🐳 containers </strong></summary>

```yaml
containers:
  container-name:     # Must match exact container_name
    # The next 5 settings are optional. They override the respective global setting for this container 
    ntfy_topic: your_topic
    ntfy_tags: "tag1, tag2"     
    ntfy_priority: 4            
    attachment_lines: 10        
    notification_cooldown: 10   
  # You don't have to use both `keywords` and `keyword_with_attachment`. One is enough. 
    keywords:                                 
      - error                                  # Simple text matches
      - regex: (username|password).*incorrect  # Use regex patterns when you need them
    # When one of these keywords is found a logfile is attached to the notification
    keywords_with_attachment:
      - critical

# If you have configured global_keywords and don't need container specific settings you can define the container name and leave the rest blank
  another-container-name:
```

 </details>


<details><summary><em>Click to expand:</em><strong> 🌍 global_keywords </strong></summary>

```yaml
# This section is optional.
# These keywords are being monitored for all containers. 
global_keywords:              
  keywords:
    - error
  keywords_with_attachment:  # When one of these keywords is found a logfile is attached
    - regex: (critical|error)
```

</details>

[Here](/config.yaml) you can find a full example config.


### 🍀 Enviroment Variables

Except for container specific settings and regex patterns you can configure most settings via docker environment variables.

<details><summary><em>Click to expand:</em><strong> Enviroment Variables </strong></summary><br>


| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `NTFY_URL`                      | URL of your Ntfy server instance                           | _N/A_    |
| `NTFY_TOKEN`                    | Authentication token for Ntfy in case you need authentication.      | _N/A_    |
| `NTFY_USERNAME`                 | Ntfy Username in case you need authentication.             | _N/A_    |
| `NTFY_PASSWORD`                 | Ntfy password in case you need authentication.             | _N/A_    |
| `NTFY_TOPIC`                    | Notification topic for Ntfy.                               | _N/A_  |
| `NTFY_TAGS`                     | Ntfy [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications. | kite,mag  |
| `NTFY_PRIORITY`                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| `APPRISE_URL`                   | Any [Apprise-compatible URL](https://github.com/caronc/apprise/wiki)  | _N/A_    |
| `CONTAINERS`                    | A comma separated list of containers. These are added to the containers from the config.yaml (if you are using one).| _N/A_     |
| `GLOBAL_KEYWORDS`       | Keywords that will be monitored for all containers. Overrides `global_keywords.keywords` from the config.yaml.| _N/A_     |
| `GLOBAL_KEYWORDS_WITH_ATTACHMENT`| Notifications triggered by these global keywords have a logfile attached. Overrides `global_keywords.keywords_with_attachment` from the config.yaml.| _N/A_     |
| `NOTIFICATION_COOLDOWN`         | Cooldown period (in seconds) per container per keyword before a new message can be sent  | 5        |
| `LOG_LEVEL`                     | Log Level for LoggiFly container logs.                    | INFO     |
| `MULTI_LINE_ENTRIES`            | When enabled the program tries to catch log entries that span multiple log lines.<br>If you encounter bugs or you simply don't need it you can disable it.| True     |
| `ATTACHMENT_LINES`              | Define the number of Log Lines in the attachment file     | 20     |
| `DISABLE_RESTART`               | Disable automatic restarts when the config file is changed.| False  |
| `DISBLE_START_MESSAGE`          | Disable startup message.                                  | False     |
| `DISBLE_SHUTDOWN_MESSAGE`       | Disable shutdown message.                                 | False     |
| `DISABLE_RESTART_MESSAGE`       | Disable message on config change when program restarts.| False     |
| `DOCKER_HOST`                   | Docker socket proxy URL                                    | _N/A_ |

</details>

---

## 💡 Tips

1. If you want to **Protect Sensitive Credentials** like tokens or Apprise URLs, store them in environment variables (not in YAML).
2. Ensure containers names **exactly match** your Docker **container names**. 
    - Find out your containers names: ```docker ps --format "{{.Names}}" ```
    - 💡 Pro Tip: Define the `container_name:` in your compose files. 
3. **Test Regex Patterns**: Validate patterns at [regex101.com](https://regex101.com) before adding them to your config.
4. **Troubleshooting Multi-Line Log Entries**. If LoggiFly only catches single lines from log entries that span over multiple lines:
    - Wait for Patterns: LoggiFly needs to process a few lines in order to detect the pattern the log entries start with (e.g. timestamps/log formats)
    - Unrecognized Patterns: If issues persist, open an issue and share the affected log samples

---

## License
[MIT](https://github.com/clemcer/LoggiFly/blob/main/LICENSE)
