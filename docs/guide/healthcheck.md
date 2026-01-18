---
title: Healthcheck
---

# Healthcheck

LoggiFly has a healthcheck that is not enabled by default. You can enable it by setting the environment variable `ENABLE_HEALTHCHECK` to `true` and configuring a healthcheck in your docker compose file.


How it works:
1. LoggiFly periodically checks whether the monitoring the monitored docker host(s) is still working 
2. If at least one docker host is still being monitored, LoggiFly writes a heartbeat file
3. The healthcheck script (called by healthcheck command from your compose file) verifies the heartbeat file exists and is recent
4. If the heartbeat becomes stale (not updated), Docker marks the container as unhealthy

The healthcheck fails when LoggiFly no longer monitors *any* docker host. This primarily happens when the docker host is unreachable.

The same thread that writes the hearbeat file also attempts to reconnect to a docker host when the connection is lost (every 60s by default).

::: info
If you use the healthcheck in your compose and *don't* set `ENABLE_HEALTHCHECK: true` the healthcheck will fail.
:::

## Compose Example

Here is an example compose file with a healthcheck that checks whether LoggiFly is healthy every 60 seconds:

<<< @/compose/compose.healthcheck.yaml{yaml}

## Environment Variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| ENABLE_HEALTHCHECK | false | Set to true to enable healthcheck |
| HEARTBEAT_INTERVAL | 60 | Seconds between heartbeat writes and docker host reconnection attempts when the connection to a docker host is lost (minimum: 3) |

::: info
The maximum allowed heartbeat age is automatically calculated as HEARTBEAT_INTERVAL * 1.5.
:::

::: tip
The compose `interval` should be bigger than `HEARTBEAT_INTERVAL` since checking more frequently than the heartbeat is written is redundant
:::

## Read-Only Containers

The default heartbeat path (`/dev/shm/loggifly-heartbeat`) uses an in-memory filesystem, so the healthcheck works with read-only containers without additional configuration.

## Multi-Host Setups

When monitoring multiple Docker hosts, the healthcheck passes as long as at least one host is being actively monitored. If all configured hosts become unreachable, the healthcheck will fail.