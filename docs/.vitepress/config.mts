import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Horus',
  description: 'AI-native security automation for small IT teams.',
  lang: 'en-US',

  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['meta', { name: 'theme-color', content: '#E8B94A' }],
  ],

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Horus Docs',

    nav: [
      { text: 'Overview', link: '/overview' },
      { text: 'API', link: '/api-reference' },
      { text: 'Agents', link: '/agents' },
      {
        text: 'GitHub',
        link: 'https://github.com/HorusAgentsSec/horus',
      },
    ],

    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Overview', link: '/overview' },
          { text: 'Deployment', link: '/deployment' },
        ],
      },
      {
        text: 'Core',
        items: [
          { text: 'Agents pipeline', link: '/agents' },
          { text: 'Scanners & intel', link: '/scanners' },
          { text: 'Data models', link: '/data-models' },
        ],
      },
      {
        text: 'Platform',
        items: [
          { text: 'API reference', link: '/api-reference' },
          { text: 'Frontend', link: '/frontend' },
          { text: 'Security & auth', link: '/security' },
          { text: 'Iris daemon', link: '/iris' },
        ],
      },
      {
        text: 'Legal',
        items: [
          { text: 'Privacy', link: '/PRIVACY' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/HorusAgentsSec/horus' },
    ],

    search: {
      provider: 'local',
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2025 Horus',
    },

    editLink: {
      pattern: 'https://github.com/HorusAgentsSec/horus/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
