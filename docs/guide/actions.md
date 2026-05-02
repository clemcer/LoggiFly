---
title: Actions
---

# Actions


## Container Actions

You can configure container actions to be triggered when a keyword/regex is found in the logs or a container event occurs. 
Supported actions are `restart`, `stop` and `start`. 

You can perform these actions on the monitored container itself or on other containers.

The `container_action_cooldown` is per action per container and defaults to 300 seconds (5 minutes) and has to be at least 10 seconds.

:::info
Note that actions require access to the docker socket and generally don't work with a Docker Socket Proxy.
:::

### Perform actions on the monitored container

```yaml
global:
  defaults:
    container_action_cooldown: 60  # 1 minute cooldown

containers:
  rules:
    - container_name: my-app
      keywords:
        # Act on log matches
        - regex: "process.*(failed|did not finish)" 
          container_action: restart  # Restart the container when this regex is found
        - keyword: critical
          container_action: stop     # Stop the container when this keyword is found
          container_action_cooldown: 10  # 10 seconds cooldown for this action

      container_events:
        # Act on container events
        - event: crash
          container_action: restart
          message_template: '{action_result_message}'
```

### Perform actions on other containers

```yaml
containers:
  rules:
    - container_name: my-app
      keywords:
        - regex: "process.*(failed|did not finish)" 
          container_action: restart@some-other-container  # Restart another container when this regex is found
        - keyword: critical
          container_action: stop@some-other-container     # Stop another container when this keyword is found
        - keyword: timeout
          container_action: start@some-other-container
```

## Trigger OliveTin Actions


[OliveTin](https://github.com/OliveTin/OliveTin) is a great tool that allows you to perform predefined commands from a web interface. Fortunately for us it also has a API that we can use to trigger actions when LoggiFly finds certain keywords in the logs.

LoggiFly will send the execution output of the action in a separate notification.

You can configure your OliveTin URL globally under `global.defaults.olivetin_url` or per `container` and even per `keyword`/`regex` in case you want to trigger commands on different OliveTin instances.

If you have configured a [Local User Login](https://docs.olivetin.app/security/local.html) you can configure `username` and `password` to trigger actions that require authentication (also in `settings`, per `container` and per `keyword`/`regex`).

### Configuring one simple action

Simply configure the [`olivetin_action_id`](https://docs.olivetin.app/action_customization/ids.html) per keyword or regex.

Here is a an example config snippet:


```yaml
global:
  defaults:
    olivetin_url: http://192.168.178.20:1337
    olivetin_username: admin
    olivetin_password: password
    
containers:
  rules:
    - container_name: my-app
      keywords:
        - regex: 'download.*failed'
          olivetin_action_id: some-action-id

```

### Configuring multiple actions with Arguments

You can configure multiple actions and pass arguments by using the `olivetin_actions` field.

```yaml
containers:
  rules:
    - container_name: my-app
      keywords:
        - keyword: critical
          olivetin_actions:
            - id: some-action-id
              arguments:
                - name: arg1
                  value: value1
                - name: arg2
                  value: value2
            - id: some-other-action-id
              arguments:
                - name: arg3
                  value: value3
                - name: arg4
                  value: value4
```