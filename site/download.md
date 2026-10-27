# 下载与安装

::: warning 安装前
请先读一遍[安全与局限](/guide/security)。如果有顾虑或者不满意，可以不安装。
:::

## 下载

每个版本的安装包同时发布在两个地方，内容相同，任选一个：

| 下载地址 | 说明 |
| --- | --- |
| [Gitee 发行版](https://gitee.com/why_y1/watch-unlock-windows/releases) | 国内网络建议用这个 |
| [GitHub Releases](https://github.com/whyy1/watch-unlock-windows/releases/latest) | GitHub 能正常打开时用 |

下载 `WatchUnlock_x.y.z_x64-setup.exe`。同一个发行版里的 `SHA256SUMS.txt` 记录了安装包的 SHA256，可以在 PowerShell 里核对：

```powershell
Get-FileHash .\WatchUnlock_x.y.z_x64-setup.exe -Algorithm SHA256
```

安装包没有代码签名，运行时 Windows 可能提示“未知发布者”。

## 安装

1. 运行下载的 `WatchUnlock_x.y.z_x64-setup.exe`。如果弹出 Windows 管理员确认，点「是」，然后按向导完成安装。
2. 从开始菜单打开 **Watch Unlock**，接着按[使用](/guide/usage)绑定手表。

卸载时，在“设置 → 应用”里找到它即可。用户数据会保留。

## 更新

程序启动时会检查新版本，发现后先显示更新内容，由你确认再下载安装；设备、密码和设置都会保留。点左下角的版本号可以查看[更新记录](/changelog)，也可以手动检查更新。

0.2.6 及更早的版本只会去 GitHub 检查更新，国内网络下可能检查不到。遇到这种情况，从上面的 Gitee 发行版手动下载新版安装一次即可。
