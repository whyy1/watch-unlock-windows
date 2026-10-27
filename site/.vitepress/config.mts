import { defineConfig } from 'vitepress'

const github = 'https://github.com/whyy1/watch-unlock-windows'

export default defineConfig({
  lang: 'zh-CN',
  title: 'Watch Unlock',
  description: '用 Apple Watch 解锁 Windows：锁屏后戴着手表走开，再走回来，电脑自动解锁。',
  // Served as a GitHub project page: https://whyy1.github.io/watch-unlock-windows/
  base: '/watch-unlock-windows/',
  cleanUrls: true,
  lastUpdated: true,
  head: [['link', { rel: 'icon', href: '/watch-unlock-windows/favicon.ico' }]],
  themeConfig: {
    logo: '/logo.png',
    nav: [
      { text: '下载', link: '/download' },
      { text: '使用指南', link: '/guide/usage' },
      { text: '更新记录', link: '/changelog' }
    ],
    sidebar: [
      {
        text: '开始',
        items: [
          { text: '下载与安装', link: '/download' },
          { text: '安全与局限', link: '/guide/security' },
          { text: '使用', link: '/guide/usage' },
          { text: '后台程序', link: '/guide/background' },
          { text: '自动锁屏（动态锁）', link: '/guide/dynamic-lock' }
        ]
      },
      {
        text: '参考',
        items: [
          { text: '解锁规则', link: '/guide/rules' },
          { text: '配对排错', link: '/guide/troubleshooting' },
          { text: '已知问题与反馈', link: '/guide/feedback' },
          { text: '更新记录', link: '/changelog' },
          { text: '许可', link: '/license' }
        ]
      }
    ],
    socialLinks: [{ icon: 'github', link: github }],
    editLink: { pattern: `${github}/edit/main/site/:path`, text: '在 GitHub 上编辑此页' },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: { buttonText: '搜索', buttonAriaLabel: '搜索' },
          modal: {
            noResultsText: '没有找到结果',
            resetButtonTitle: '清除',
            footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' }
          }
        }
      }
    },
    outline: { label: '本页目录', level: [2, 3] },
    docFooter: { prev: '上一页', next: '下一页' },
    lastUpdated: { text: '最后更新' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '目录',
    darkModeSwitchLabel: '外观',
    lightModeSwitchTitle: '切换到浅色',
    darkModeSwitchTitle: '切换到深色',
    footer: {
      message: '按 GNU AGPL v3 发布。本项目与 Apple 无关。',
      copyright: '基于 xiaoka520/watch-unlock-windows 修改'
    }
  }
})
