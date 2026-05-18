---
title: Notifications Section
---


# Notifications

In the config.yaml under the `notifications` section you can configure the following notification services:
- [ntfy](#ntfy)
- [Apprise](#apprise)
- [Custom Webhook](#custom-webhook)

You can also set all three notification services at the same time.

In this section only yaml configuration is shown. Environment variables are also supported and can be found [here](../environment-variables#notifications).

::: info
All notification settings can also be applied individually per container or per keyword/regex pattern (see [containers section](./containers#settings-per-container-and-keyword)).
:::


## ntfy

[ntfy](https://ntfy.sh/) is a simple, self-hostable notification service. 

See full configuration example below

### Configuration Options

| Name | Required | Description |
|------|----------|-------------|
| **Connection Settings** | | |
| `url` | ✅ | The URL of your ntfy instance |
| `topic` | ✅ | The topic name for ntfy |
| **Authentication** | | |
| `token` | ❌ | Token for ntfy authentication |
| `username` | ❌ | Username for ntfy authentication (requires password) |
| `password` | ❌ | Password for ntfy authentication (requires username) |
| **Message Options** | | |
| `priority` | ❌ | [Message priority](https://docs.ntfy.sh/publish/?h=priorit#message-priority) from 1 (low) to 5 (high), defaults to 3 |
| `tags` | ❌ | Comma-separated [tags/emojis](https://docs.ntfy.sh/publish/?h=tags#tags-emojis) for the notification (e.g., `warning,fire`) |
| `icon` | ❌ | [Icon URL](https://docs.ntfy.sh/publish/?h=icon#icons) to display with the notification (defaults to LoggiFly logo) |
| `click` | ❌ | [URL to open](https://docs.ntfy.sh/publish/?h=click#click-action) when the notification is clicked |
| `markdown` | ❌ | Enable [markdown formatting](https://docs.ntfy.sh/publish/?h=markdo#markdown-formatting) in message (true/false), defaults to false |
| **Advanced** | | |
| `actions` | ❌ | List of [action buttons](https://docs.ntfy.sh/publish/?h=actions#action-buttons) to add to the notification (see section below) |
| `headers` | ❌ | Custom HTTP headers as key-value pairs (see section below) |

### ntfy actions
You can add up to **3 interactive action buttons** to your notifications using [ntfy actions](https://docs.ntfy.sh/publish/?h=actions#defining-actions).
::: details

**Supported Action Types:**

| Action Type | Description |
|-------------|-------------|
| `view` | Opens a URL when clicked |
| `http` | Sends an HTTP request when clicked |
| `broadcast` | Sends an Android broadcast intent (Android only) |

Here is how to configure each action type:

::: code-group
```yaml [view action]
ntfy:
  actions:
    - action: "view"                      # required
      label: "View Container"             # required
      url: "https://example.com/view"     # required
      clear: false                        # optional, defaults to false
```
```yaml [http action]
ntfy:
  actions:
    - action: "http"                      # required
      label: "Restart Service"            # required
      url: "https://example.com/restart"  # required
      method: "POST"                      # optional, defaults to POST
      headers:                            # optional
        Authorization: "Bearer token"
        X-Custom-Header: "value"
      body: "{\"service\": \"web\"}"      # optional
      clear: false                        # optional, defaults to false
```

```yaml [broadcast action]
ntfy:
  actions:
    - action: "broadcast"                     # required
      label: "Take Action"                    # required
      intent: "io.heckel.ntfy.USER_ACTION"    # optional, defaults to io.heckel.ntfy.USER_ACTION
      extras:                                 # optional
        action: "custom_action"
        value: "123"
      clear: false                            # optional, defaults to false
```

:::


### Custom ntfy headers

You can also set custom headers to send with the request.

::: details Example ntfy headers

```yaml
headers:
  At: "tomorrow, 10am" # ntfy delay feature. send the notification at 10am tomorrow
  X-Custom-Header: "Test123" # custom header
```
:::

### Full example

```yaml [ntfy]
notifications:                       
  ntfy:
    url: http://your-ntfy-server    # Required. The URL of your ntfy instance
    topic: loggifly                 # Required. the topic for ntfy
    # authentication options
    token: ntfy-token               # ntfy token in case you need authentication 
    username: john                  # ntfy Username + Password in case you need authentication 
    password: password              # ntfy Username + Password in case you need authentication 
    # optional settings
    priority: 3                     # ntfy priority (1-5)
    tags: kite,mag                  # ntfy tags/emojis 
    icon: https://example.com/icon.png # ntfy icon
    click: https://example.com/click # ntfy click
    markdown: true                  # ntfy markdown
    actions:                        # ntfy actions
      - action: "view"
        label: "View"
        url: "https://example.com/view"
    headers:                        # add headers if needed
      Authorization: "Bearer token"
      X-Custom-Header: "Test123"
```


## Apprise

[Apprise](https://github.com/caronc/apprise) allows you to send notifications to a wide variety of services using a simple URL-based configuration.

See which services are supported [here](https://github.com/caronc/apprise/wiki).

### Configuration Options

| Name | Required | Description |
|------|----------|-------------|
| `url` | ✅ | Any [Apprise-compatible URL](https://github.com/caronc/apprise/wiki) (e.g., `discord://webhook-url`, `mailto://user:pass@gmail.com`, `slack://token`) |

### Example

```yaml
notifications:
  apprise:
    url: "discord://webhook-url"
```

## Custom Webhooks

Send notification data to your own custom endpoint for integration into custom workflows. LoggiFly will send all data in JSON format.


### Configuration Options

| Name | Required | Description |
|------|----------|-------------|
| `url` | ✅ | The URL of your custom webhook endpoint |
| `headers` | ❌ | Custom HTTP headers as key-value pairs (e.g., for authentication) |

### Example

```yaml
notifications:
  webhook:
    url: https://custom.endpoint.com/post
    headers:
      Authorization: "Bearer token"
      X-Custom-Header: "Test123"
```


::: info
The webhook always sends `title` and `message` in the JSON payload. 
For non-system notifications, it also sends `info_fields` which are [these always available template fields](../customize-notifications/index.md#always-available-template-fields) and `log_fields.json` which is just the whole json log entry if the log is in json format (see [json templating](../customize-notifications/json)) and `log_fields.regex` (see [regex templating](../customize-notifications/regex)).
:::
::: warning
The webhook feature may be expanded on in the future and can be subject to change.
::: 