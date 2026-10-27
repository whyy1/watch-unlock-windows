# 开发与构建

## 环境

- Windows 10/11 x64，以及 Microsoft Edge WebView2 Runtime。
- Rust 1.90 或更高版本；Node.js 20.19+ 或 22.12+。
- 推荐使用 MSVC 加 Windows SDK，参见 [Tauri 前提条件](https://v2.tauri.app/start/prerequisites/)。也可以用 GNU 工具链，但需要完整的 LLVM-MinGW，因为编译 Tauri 资源要用到 `windres` 和 C 预处理器。

## 构建命令

所有步骤都通过 `scripts/Build.ps1` 执行。如果仓库里有 `.tools/`，脚本会优先使用其中的便携 Rust，否则使用 PATH 里的 Rust。

```powershell
./scripts/Build.ps1 -Action doctor    # 检查 Rust、Node、npm 和资源编译器
./scripts/Build.ps1 -Action test      # 后端测试
./scripts/Build.ps1 -Action desktop   # 前端构建与测试、桌面宿主测试与编译
./scripts/Build.ps1 -Action package   # 全部测试，生成安装程序
```

使用 GNU 工具链时需要再加上 `-ResourceToolsRoot <LLVM-MinGW 根目录>`。需要的话，还可以用 `-RustToolsRoot`、`-RustToolchain` 指定 Rust。这三个参数也可以分别通过环境变量 `WATCH_UNLOCK_RESOURCE_TOOLS`、`WATCH_UNLOCK_TOOL_ROOT`、`WATCH_UNLOCK_RUST_TOOLCHAIN` 设置。构建日志写在 `artifacts/build/`。

## 安装程序

`package` 按以下顺序执行：
1. 生成第三方许可清单（`scripts/Export-ThirdPartyNotices.ps1`）；
2. 运行全部测试，并编译后端的 release 版本；
3. 执行 `tauri build --bundles nsis`，生成安装程序和它的更新签名；
4. 在 `dist/` 中输出 `WatchUnlock_x.y.z_x64-setup.exe`、`.sig`、`latest.json`（更新清单，说明取自 `CHANGELOG.md` 中当前版本那一节）和 `SHA256SUMS.txt`。

第一次打包时，Tauri 会自动下载免费的 NSIS 工具，放在 Tauri 自己的缓存目录里。

安装程序的内容由 `apps/desktop/src-tauri/tauri.conf.json` 中的 `bundle.resources` 决定：
- 界面程序 `WatchUnlock.exe` 和 `WebView2Loader.dll`；
- 后台 `watchd.exe`、`watchd-supervisor.exe`；
- 登录组件 DLL；
- `LICENSE`、`NOTICE` 和 `licenses/`。

安装默认是“所有用户”模式，装到 `Program Files\Watch Unlock`。`apps/desktop/src-tauri/installer.nsh` 中的钩子负责以下工作：

| 时机 | 操作 |
| --- | --- |
| 安装前 | 停止旧的后台；把正在被 LogonUI 占用的旧 DLL 改名，重启后删除 |
| 安装后 | 在 HKLM 中注册 Credential Provider；在当前用户的 `Run` 项里写入开机自启 |
| 卸载时 | 停止后台，删除以上注册表项 |

用户数据（`%LOCALAPPDATA%\WatchUnlockWindows\`）在卸载时会保留。

登录组件只信任与它的 DLL 位于同一目录、并且该目录在 Program Files 之内的 `watchd.exe`。在开发目录里运行的后台可以扫描和保存配置，但无法真正解锁；要在真机上验证，请打包后运行 setup.exe。

## 自动更新与签名密钥

应用通过 `tauri-plugin-updater` 读取 `tauri.conf.json` 中 `plugins.updater.endpoints` 列出的 `latest.json`，只接受用 `pubkey` 对应私钥签名的安装包。

- 发版前先在 `CHANGELOG.md` 里写好 `## x.y.z` 一节，并同步修改 `tauri.conf.json`、`src-tauri/Cargo.toml`、`package.json` 的版本号；缺少这一节时打包会报错。
- 私钥用 `npx tauri signer generate` 生成。打包时优先读取环境变量 `TAURI_SIGNING_PRIVATE_KEY`（和 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`）；没有设置时，读取本机用 DPAPI 加密保存的 `%USERPROFILE%\.watch-unlock\updater-key.dpapi`，只在打包进程的环境变量里解密。
- **私钥必须另外备份（例如放进密码管理器）。私钥一旦丢失，已经安装的用户就再也无法自动更新，只能手动下载新版安装。** 私钥不能提交到仓库。
- 国内用户访问 GitHub 下载不稳定，所以 `endpoints` 先查 Gitee 镜像 `why_y1/watch-unlock-windows` 上 `main` 分支的 `updates/latest-gitee.json`，失败了再查 GitHub。打包时会顺带写出这个文件，下载地址指向 Gitee 发行版；用 `-GiteeRepo owner/repo`（或环境变量 `WATCH_UNLOCK_GITEE_REPO`）可以换仓库，传 `-GiteeRepo ''` 则不生成。

发版：打包后把 `updates/latest-gitee.json` 和其他改动一起提交，然后运行 `./scripts/Publish.ps1`。脚本依次执行：

1. 给当前提交打 `v<版本>` 标签，推送到 `origin` 和 `gitee`。没有配置的远程会跳过。
2. 用 `gh` 创建 GitHub Release，上传安装程序、`.sig`、`latest.json` 和 `SHA256SUMS.txt`。
3. 通过 Gitee API 创建同名发行版，上传同样的附件，并核对安装程序的下载地址和 `updates/latest-gitee.json` 里写的一致。
4. 最后推送 `main`。Gitee 上的更新清单要等这一步推送后才生效，这时附件已经传好了。

中途失败时修好问题再运行一次即可，已经建好的发行版和已经上传的附件会跳过。加 `-WhatIf` 只做检查，不发布。

Gitee 需要一个勾选了 `projects` 权限的私人令牌（Gitee「设置」→「私人令牌」）。优先读取环境变量 `WATCH_UNLOCK_GITEE_TOKEN`，没有设置时读取用 DPAPI 加密保存的 `%USERPROFILE%\.watch-unlock\gitee-token.dpapi`。保存方法：

```powershell
Read-Host '粘贴 Gitee 私人令牌' -AsSecureString | ConvertFrom-SecureString |
    Set-Content -LiteralPath "$env:USERPROFILE\.watch-unlock\gitee-token.dpapi"
```

令牌只放在请求正文里发送，不会出现在命令行或输出中。

## 开发界面

```powershell
cd apps/desktop
npm ci
npm run dev                       # 浏览器预览，不连接后端
$env:WATCH_UNLOCK_BACKEND = (Resolve-Path '../../backend/target/release/watchd.exe').Path
npm run tauri dev                 # 连接本机编译的 watchd
```

## 提交前

运行 `scripts/Check-Release.ps1`，不要强制添加被忽略的文件：`.tools/`、构建产物、日志、`.dpapi`、`.blob`。
