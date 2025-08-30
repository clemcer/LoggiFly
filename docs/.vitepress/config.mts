import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "LoggiFly",
  description: "LoggiFly Documentation",
  head: [['link', { rel: 'icon', href: '/loggifly/icon.png' }]],
  base: '/loggifly/',
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    search: {
      provider: 'local'
    },
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/what-is-loggifly' },
      { text: 'Releases', link: 'https://github.com/clemcer/loggifly/releases'},
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is LoggiFly', link: '/guide/what-is-loggifly' },
          { text: 'Getting Started', link: '/guide/getting-started' }
        ]
      },
       {
        text: 'Other Platforms',
        items: [
          { text: 'Docker Swarm', link: '/guide/swarm' },
          { text: 'Podman', link: '/guide/podman' }
        ]
      },
      {
        text: 'Configuration',
        items: [
          { text: 'Configuration Walkthrough',
            collapsed: true,
            items: [
              { text: 'Overview', link: '/guide/config_sections/' },
              { text: 'Settings', link: '/guide/config_sections/settings' },
              { text: 'Notifications', link: '/guide/config_sections/notifications' },
              { text: 'Containers', link: '/guide/config_sections/containers' },
              { text: 'Global Keywords', link: '/guide/config_sections/global-keywords' },

            ]
          },
          { text: 'Configuration via Labels', link: '/guide/config_sections/label-config' },
          { text: 'Settings Overview', link: '/guide/settings-overview' },
          { text: 'Environment Variables', link: '/guide/environment-variables' },
        ]
      },
      {
        text: 'Advanced Features',
        items: [
          { text: 'Customize Notifications',
            collapsed: true,
            items: [
              { text: 'Overview', link: '/guide/customize-notifications/' },
              { text: 'JSON Logs', link: '/guide/customize-notifications/json_template' },
              { text: 'Plain Text Logs', link: '/guide/customize-notifications/template' },
            ]
          },
          { text: 'Actions', link: '/guide/actions' },
          { text: 'Remote Hosts', link: '/guide/remote-hosts' },
        ]
      },
      {
        text: 'Other',
        items: [
          { text: 'Examples', link: '/guide/examples' },
          { text: 'Tips & Troubleshooting', link: '/guide/tips' },
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/clemcer/loggifly' }
    ]
  }
})