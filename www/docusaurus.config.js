// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import { themes as prismThemes } from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'ghidriff',
  tagline: 'Python Command-Line Ghidra Binary Diff Engine',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://clearbluejar.github.io/',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/ghidriff',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'clearbluejar', // Usually your GitHub org/user name.
  projectName: 'ghidriff', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },
  markdown: {
    mermaid: true,
    format: 'detect',
  },
  themes: ["@docusaurus/theme-mermaid"],
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/clearbluejar/ghidriff/tree/main/www/docs',
        },

        gtag: {
          trackingID: "X-XXXXXXXXXX",
          anonymizeIP: true,
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
          ignorePatterns: ['/tags/**'],
          filename: 'sitemap.xml',
        },

        // blog: {
        //   showReadingTime: true,
        //   // Please change this to your repo.
        //   // Remove this to remove the "edit this page" links.
        //   editUrl:
        //     'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
        // },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],
  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'diffs',
        path: 'diffs',
        routeBasePath: 'diffs',
        sidebarPath: './diff-sidebars.js',
        editUrl:
          'https://github.com/clearbluejar/ghidriff/tree/main/www/diffs',
        // ... other options
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/github-social-ghidriff.png',
      navbar: {
        title: 'ghidriff',
        logo: {
          alt: 'ghidriff: Ghidra Binary Diffing Engine',
          src: 'img/logo.svg',
        },
        items: [
          //left
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Docs',
          },
          {
            type: 'docSidebar',
            docsPluginId: 'diffs',
            sidebarId: 'diffSidebar',
            position: 'left',
            label: 'Diffs',
          },
          //{ to: '/blog', label: 'Blog', position: 'left' },
          // right
          {
            href: 'https://github.com/clearbluejar/ghidriff',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Tutorial',
                to: '/docs/ghidriff',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'Mastadon',
                href: 'https://infosec.exchange/@clearbluejar',
              },
              {
                label: 'Twitter',
                href: 'https://twitter.com/clearbluejar',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
              {
                label: 'GitHub',
                href: 'https://github.com/facebook/docusaurus',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} ghidriff. Built with Python, Ghidra, and Markdown`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['powershell', 'diff'],
      },
    }),
};

export default config;
