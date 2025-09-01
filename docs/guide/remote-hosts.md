---
title: Remote Hosts
---

# Remote Hosts

LoggiFly supports connecting to **multiple remote hosts**.<br>
Remote hosts can be configured by providing a **comma-separated list of addresses** in the `DOCKER_HOST` environment variable.<br>
To use **TLS** you have to mount `/certs` in the volumes section of your docker compose.<br>
LoggiFly expects the TLS certificates to be in `/certs/{ca,cert,key}.pem` or in case of multiple hosts `/certs/{host}/{ca,cert,key}.pem` with `{host}` being either the IP or FQDN.<br>

::: info
When the connection to a docker host is lost, LoggiFly will try to reconnect every 60s.
:::

## Labels 
When multiple hosts are set LoggiFly will use **labels** to differentiate between them both in notifications and in logging.<br>
You can set a **label** by appending it to the address with `"|"` ([_see example_](#remote-hosts-example)).<br>
When no label is set LoggiFly will use the **hostname** retrieved via the docker daemon. If that fails, usually because `INFO=1` has to be set when using a proxy, the labels will just be `Host-{Nr}`.<br>

::: tip
If you want to set a label to your _mounted docker socket_ you can do so by adding `unix:///var/run/docker.sock|label` in the `DOCKER_HOST` environment variable (_the socket still has to be mounted_) or just set the address of a [socket proxy](#socket-proxy) with a label.
:::

### Assign Containers to Hosts

You can assign containers to specific hosts by providing a comma-separated list of labels/hostnames under the `hosts` field in the container configuration. The [labels](#labels) section shows how the hostname is constructed.<br> 
When no hosts are set LoggiFly will look for the container on _all_ configured remote hosts.

Here is a short yaml snippet showing how to assign a container to a specific host:

  
```yaml 
containers:
  container1:
    hosts: foo,bar  # This container will only be monitored on hosts with the labels 'foo' and 'bar'
    keywords:
      - error
```

## Remote Hosts Example

In this example, LoggiFly monitors container logs from the **local host** via a mounted Docker socket, as well as from **two remote Docker hosts** configured with TLS. One of the remote hosts is referred to as ‘foobar’. The local host and the second remote host have no custom label and are identified by their respective hostnames.


```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly 
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./loggifly/config:/config # Place your config.yaml here if you are using one
      - ./certs:/certs
      # Assuming the Docker hosts use TLS, the folder structure for the certificates should be like this:
      # /certs/
      # ├── 192.168.178.80/
      # │   ├── ca.pem
      # │   ├── cert.pem
      # │   └── key.pem
      # └── 192.168.178.81/
      #     ├── ca.pem
      #     ├── cert.pem
      #     └── key.pem
    environment:
      TZ: Europe/Berlin
      DOCKER_HOST: tcp://192.168.178.80:2376,tcp://192.168.178.81:2376|foobar
    restart: unless-stopped
```

## Socket Proxy

The simplest way to use LoggiFly with remote hosts is to use a docker socket proxy. Just take a look at the [docker compose examples](./getting-started#docker-compose) and set up the socket proxy on your remote host.

::: info
Container restart/stop actions are not supported when using a Docker Socket Proxy unless you use the compose example with `tecnativa/docker-socket-proxy` and `POST=1` is enabled.
:::

