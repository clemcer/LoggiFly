---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "LoggiFly"
  text: "Get Alerts from your Docker Container Logs"
  # tagline: My great project tagline
  image:
    src: /icon.png
    alt: LoggiFly Logo

  actions:
    - theme: brand
      text: Get Started  
      link: /guide/getting-started
    - theme: alt
      text: GitHub
      link: https://github.com/clemcer/loggifly
    - theme: alt
      text: Buy me a Coffee
      link: https://www.buymeacoffee.com/clemcer

features:
  - title: Plain Text, Regex & Multi-Line Log Detection
    details: Catch simple keywords or complex patterns in log entries that span multiple lines.
    icon: 🔍
  - title: Notifications
    details: Send notifications directly to ntfy or via Apprise to 100+ different services (Slack, Discord, Telegram) or even to your own custom endpoint.
    icon: 🚨
  - title: Container Events
    details: Monitor container events like crashes, restarts, starts and stops.
    icon: 🐳
  - title: Trigger Actions
    details: You can trigger OliveTin actions or configure actions like restart or stop for your containers.
    icon: 🎯
    linkText: Learn More
    link: /guide/actions
  - title: Log Attachments
    details: Automatically include a log file with your notification for better context.
    icon: 📁
  - title: Automatic Reload on Config Change
    details: LoggiFly automatically reloads the config.yaml when changes are detected.
    icon: ⚡
  - title: Configurable Alerts
    details: Format log messages with templates and only display the relevant information.
    icon: 📝
    linkText: Learn More
    link: /guide/customize-notifications
  - title: Remote Hosts
    details: Monitor and receive alerts from multiple remote Docker hosts.
    icon: 🌐
    linkText: Learn More
    link: /guide/remote-hosts
  - title: Flexible Configuration
    details: You can configure LoggiFly via a YAML file, environment variables or in the Docker labels of the container you want to monitor.
    icon: 🔧

---

