---
title: Config Structure
---

# Config Structure

The `config.yaml` file is divided into four main sections:

1. [**`settings`**](./settings): Global settings for the whole program (_Optional since they all have default values_)
2. [**`notifications`**](./notifications): Configure ntfy, apprise and/or a custom webhook
3. [**`containers`**](./containers): Define which Containers to monitor and their specific Keywords (_plus optional settings_).
4. [**`global_keywords`**](./global-keywords): Keywords that apply to _all_ monitored Containers.


## Config Template

Here is an example config for reference showing all available configuration options from this configuration walkthrough.
::: details Config Template

<<< @/configs/config_template.yaml{yaml}

:::

