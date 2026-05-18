---
title: Tips
---


# 💡 Tips

1. Ensure containers names **exactly match** your Docker **container names**. 
    - Find out your containers names: 
    ```sh
    docker ps --format "{{.Names}}"
    ```
    - Or better: Define the `container_name` in your compose files.
2. **Regex**:
   - Validate patterns against the log entries you want to catch at [regex101.com](https://regex101.com) before adding them to your config.
   - use `hide_regex_in_title: true` when using very long regexes to have a cleaner notification title<br> (or hide found keywords from the title altogether with your own custom `title_template` ([Customize Notifications](./customize-notifications/index.md#template-fields-reference))
3. **Troubleshooting Multi-Line Log Entries**. If LoggiFly only catches single lines from log entries that span over multiple lines:
    - Wait for Patterns: LoggiFly needs to process a few lines in order to detect the pattern the log entries start with (e.g. timestamps/log level)
    - Unrecognized Patterns: If issues persist, open an issue and share the affected log samples


