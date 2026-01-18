---
title: What is LoggiFly
---

# What is LoggiFly 

LoggiFly is a small, open-source tool that watches the logs and events of your docker containers and sends notifications or triggers actions when a specific keywords is found or a container event occurs.

This allows you to easily monitor containers and catch problems early without having to set up a full logging stack.

LoggiFly is also a great tool to get notifications from apps that don't have good notification support. 

::: details Screenshots
![Collage of Screenshots](/collage.png)

### Customize notifications and filter log lines for relevant information

![Custom Templates Collage](/template_collage.png)
:::


Besides sending notifications, LoggiFly can also restart, start or stop containers automatically, trigger OliveTin actions, attach log files to your notifications, format messages by extracting only the relevant information and more.

You can configure LoggiFly via environment variables, a `config.yaml` file or in the Docker labels of the containers you want to monitor. <br>
The config.yaml is very flexible and allows you to configure settings globally, per container and even per trigger (eg. keyword, regex, container event).

LoggiFly is easy to deploy, flexible, and made for people who want to monitor containers without extra complexity.

**Ideal For**:
- ✅ Catching security breaches (e.g., failed logins in Vaultwarden)
- ✅ Debugging crashes with attached log context
- ✅ Restarting containers on specific errors or stopping them completely to avoid restart loops
- ✅ Monitoring custom app behaviors (e.g., failed logins or when a user downloads an audiobook on your Audiobookshelf server)
