<a name="readme-top"></a>

<div align="center">
  <a href="clemcer/loggifly">
    <img src="/docs/public/icon.png" alt="Logo" width="200" height="auto">
  </a>
</div>
<h1 align="center">LoggiFly</h1>

  <p align="center">
    <a href="https://clemcer.github.io/loggifly/">Documentation</a>
    <a href="https://github.com/clemcer/loggifly/issues">Report Bug</a>
    <a href="https://github.com/clemcer/loggifly/issues">Request Feature</a>
  </p>



**LoggiFly** - A Lightweight Tool that monitors Docker Container Logs for predefined keywords or regex patterns and sends Notifications.

Get instant alerts for security breaches, system errors, or custom patterns through your favorite notification channels. 🚀


**Ideal For**:
- ✅ Catching security breaches (e.g., failed logins in Vaultwarden)
- ✅ Debugging crashes with attached log context
- ✅ Restarting containers on specific errors or stopping them completely to avoid restart loops
- ✅ Monitoring custom app behaviors (e.g., when a user downloads an audiobook on your Audiobookshelf server)


<div align="center">
   <img src="/docs/public/vault_failed_login.gif" alt="Failed Vaultwarden Login" width="auto" height="200">
</div>

---


# Features

- **🔍 Plain Text, Regex & Multi-Line Log Detection**: Catch simple keywords or complex patterns in log entries that span multiple lines.
- **🚨 Ntfy/Apprise Alerts**: Send notifications directly to Ntfy or via Apprise to 100+ different services (Slack, Discord, Telegram) or even to your own custom endpoint.
- **🔁 Trigger Stop/Restart**: A restart/stop of the monitored container can be triggered on specific critical keywords.
- **📁 Log Attachments**: Automatically include a log file to the notification for context.
- **⚡ Automatic Reload on Config Change**: The program automatically reloads the `config.yaml` when it detects that the file has been changed.
- **📝 Configurable Alerts**: Filter log lines for relevant information and use templates for your messages and notification titles.
- **🌐 Remote Hosts**: Connect to multiple remote Docker hosts.
- **🐳 Multi-Platform Support**: LoggiFly runs on Docker, Docker Swarm and Podman


---
# Screenshots

<div style="display: flex; justify-content: center; gap: 10px; align-items: center;">
  <img src="/docs/public/collage.png" alt="collage of screenshots" object-fit: contain;">
</div>

<br>

### Customize notifications and filter log lines for relevant information:

<div style="display: flex; justify-content: center; gap: 10px; align-items: center;">
  <img src="/docs/public/template_collage.png" alt="Custom Tepmplates Collage" object-fit: contain;">
</div>

## Documentation
- [Documentation](https://clemcer.github.io/loggifly/)
- [Getting Started](https://clemcer.github.io/loggifly/guide/getting-started)
- [Configuration](https://clemcer.github.io/loggifly/guide/config)

# Support

If you find LoggiFly useful, drop a ⭐️ on the repo or buy me a coffee!

<p>
    <a href="https://www.buymeacoffee.com/clemcer" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>
    <a href="https://ko-fi.com/clemcer" target="_blank"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support on Ko-fi" height="50"></a>
</p>


# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=clemcer/loggifly&type=Date)](https://www.star-history.com/#clemcer/loggifly&Date)

## License
[MIT](https://github.com/clemcer/LoggiFly/blob/main/LICENSE)
