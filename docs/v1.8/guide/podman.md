---
title: Podman
---

# Podman

LoggiFly can also be used with Podman.<br>
When running the container as root you can just use the docker compose file and start the container with `podman-compose up -d`. 
Just make sure to mount your Podman socket and set the environment variable `DOCKER_HOST` to the socket, e.g. `DOCKER_HOST=unix:///run/user/1000/podman/podman.sock`. <br>

When running the container rootless it is a bit more complicated.<br>
You have to set the `userns` which unfortunately can not be set in the docker compose.<br>
So your two options are to either use a `podman run` command or create a podman quadlet file and run it via `systemctl --user start loggifly`. <br>
  
Sometimes the `User` and `SecurityLabelDisable` options have to be set as well. <br>

## Podman Run

Here is an example of how to run LoggiFly with a Podman run command. <br>


```bash

podman run -d \
  --name loggifly \
  --userns keep-id:uid=1000,gid=1000 \
  -v /run/user/1000/podman/podman.sock:/run/user/1000/podman/podman.sock \
  -v /path/to/config.yaml:/config/config.yaml \
  -e DOCKER_HOST=unix:///run/user/1000/podman/podman.sock \
  -e CONTAINERS="container1,container2" \
  -e GLOBAL_KEYWORDS="error,critical" \
  ghcr.io/clemcer/loggifly:latest
```

You might also need these two options depending on your setup:

```bash
  --security-opt label=disable \  # only necessary if SElinux prohibits the access of sockets from inside the container
  --user 1000:1000 \              # might be necessary depending on your setup
```

## Podman Quadlet File

Here is an example of how to run LoggiFly with a Podman quadlet file. <br>

Place the following file in  `~/.config/containers/systemd/loggifly.container` and edit it to suit your needs:

```ini
[Unit]
Description=Loggifly container
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=loggifly
Image=ghcr.io/clemcer/loggifly:latest
AutoUpdate=registry # auto update of image, podman-auto-update.timer needs to run for it to work
Environment=CONTAINERS="container1,container2"
Environment=GLOBAL_KEYWORDS="error,failed login,password"
Environment=GLOBAL_KEYWORDS_WITH_ATTACHMENT="critical"
Environment=APPRISE_URL=<apprise url>
Environment=DOCKER_HOST=unix:///run/user/1000/podman/podman.sock
Volume=/path/to/config:/config
Volume=/run/user/1000/podman/podman.sock:/run/user/1000/podman/podman.sock
UserNS=keep-id:uid=1000,gid=1000 
#User=1000:1000            # might be necessary depending on your setup
#SecurityLabelDisable=true # only necessary if SElinux prohibits the access of sockets from inside the container

[Service]
Restart=always

[Install]
WantedBy=multi-user.target default.target # default target is only necessary if a start at boot is desired

```

Start the container with:

```bash 
systemctl --user start loggifly
```
