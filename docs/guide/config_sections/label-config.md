---
title: Configuration via DockerLabels
---

# Configuration via Docker Labels

You can configure keywords and settings in the Docker labels of the containers you want to monitor.

Pretty much every setting can be configured via Docker labels on `container` and on `keyword` / `regex` level.

Every label has to start with `loggifly` and you have to set `loggifly.monitor` to `true` for the container to be monitored. If you set it to `false` the container will always be ignored even it is configured in your `config.yaml`.

Container-level settings are set via `loggifly.<setting>`. 

To provide a simple list of keywords, you can set `loggifly.keywords` to a comma-separated list of keywords. The same applies for `loggifly.excluded_keywords`.

If you want to set keyword-level settings, you can do so by setting `loggifly.keywords.<index>.<setting>`. 
So if you wanted to set a regex with a `title_template`, you can do so by setting `loggifly.keywords.1.regex: "some-regex"` and `loggifly.keywords.1.title_template: "some-title"`.

The same applies for container events. You can set `loggifly.container_events` to a comma-separated list of container events or add settings for a specific event by setting `loggifly.container_events.<index>.event: crash` and and`loggifly.container_events.<index>.<setting>: <some-value>`.

## Example

```yaml
services:
  container1:
    image: my-container
    labels:
      loggifly.monitor: "true" # has to be set

      # container-level settings
      loggifly.apprise_url: "discord://webhook-url"
      loggifly.ntfy_tags: "closed_lock_with_key"
      loggifly.ntfy_priority: "3"
      loggifly.attach_logfile: "true" # always attach the logfile to the notification for this container

      # comma-separated lists for keywords and excluded keywords on container level
      loggifly.keywords: "keyword1,keyword2,keyword3"
      loggifly.excluded_keywords: "keyword4,keyword5,keyword6"
      
      # simple keyword with notification title
      loggifly.keywords.0: "critical" 
      loggifly.keywords.0.title_template: "{container}: Critical Alert"
      
      # regex with ntfy tags
      loggifly.keywords.1.regex: 'download.*failed' 
      loggifly.keywords.1.ntfy_tags: "partying_face"
      
      # simple keyword with actions
      loggifly.keywords.2.keyword: "timeout" 
      loggifly.keywords.2.action: "restart"

      # comma-separated list of container events
      loggifly.container_events: "oom,die,destroy"

      # container event with action and title_template
      loggifly.container_events.0.event: "crash"
      loggifly.container_events.0.action: "restart"
      loggifly.container_events.0.title_template: "{container} crashed with exit code {exit_code}"

  ```


## Using Labels with Swarm Services

While you can set labels under the `deploy` section in the compose file of your Swarm Service, it is recommended to set them directly in the `labels` section of the container since LoggiFly can not read Swarm Service Labels when running on a worker node.

```yaml
services:
  webserver:
    image: nginx

    # With these labels LoggiFly would only monitor containers
    # of the nginx service that are running on manager nodes
    deploy:
      labels:
        loggifly.monitor: "true" 

    # With these labels LoggiFly would monitor all containers 
    # of the nginx service, both on manager and worker nodes
    labels:
      loggifly.monitor: "true"  
```
