import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "LoggiFly",
  description: "LoggiFly Documentation",
  head: [['link', { rel: 'icon', href: '/LoggiFly/favicon.ico' }]],
  base: '/LoggiFly/',
  cleanUrls: true,  
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config

    outline: [2, 4],
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
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Migrate to v2', link: '/guide/migrate-to-v2' },
        ]
      },
       {
        text: 'Other Platforms',
        items: [
          { text: 'Swarm', link: '/guide/swarm' },
          { text: 'Podman', link: '/guide/podman' }
        ]
      },
      {
        text: 'Configuration',
        items: [
          { text: 'Configuration Walkthrough',
            collapsed: true,
            items: [
              { text: 'Overview', link: '/guide/config/' },
              { text: 'Settings', link: '/guide/config/settings' },
              { text: 'Global', link: '/guide/config/global' },
              { text: 'Notifications', link: '/guide/config/notifications' },
              { text: 'Containers & Rules', link: '/guide/config/containers-and-rules' },
              { text: 'Keywords & Triggers', link: '/guide/config/keywords-and-triggers' },

            ]
          },
          { text: 'Config Schema', link: '/guide/schema/' },
          { text: 'Environment Variables', link: '/guide/environment-variables' },
          { text: 'Configuration via Labels', link: '/guide/config/label-config' },
        ]
      },
      {
        text: 'Advanced',
        items: [
          { text: 'Customize Notifications',
            collapsed: true,
            items: [
              { text: 'Overview', link: '/guide/customize-notifications/' },
              { text: 'Extract from JSON', link: '/guide/customize-notifications/json' },
              { text: 'Extract from Regex', link: '/guide/customize-notifications/regex' },
            ]
          },
          { text: 'Actions', link: '/guide/actions' },
          { text: 'Remote Hosts', link: '/guide/remote-hosts' },
          { text: 'Healthcheck', link: '/guide/healthcheck' },
        ]
      },
      {
        text: 'Other',
        items: [
          { text: 'Examples', link: '/guide/examples' },
          { text: 'Tips & Troubleshooting', link: '/guide/tips' },
          { text: 'Support the Project', link: '/support' },
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/clemcer/loggifly' }
    ]
  }
})
