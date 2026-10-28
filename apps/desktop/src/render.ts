import { icon } from "./icons";
import { native } from "./bridge";
import type {
  Device,
  DeviceSignal,
  HistoryEntry,
  ObservedDevice,
  PairedDevice,
  PairingStatus,
  Page,
  RuntimeStatus,
  SetupStatus,
  Snapshot,
  Signal,
} from "./types";

export const escape = (value: unknown): string =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c] as string,
  );

export function sparkline(samples: number[]): string {
  if (!samples.length) return '<div class="chart-empty">等待真实信号</div>';
  const points = samples
    .map(
      (rssi, i) =>
        `${8 + (i * 284) / Math.max(samples.length - 1, 1)},${68 - ((Math.max(-100, Math.min(-30, rssi)) + 100) / 70) * 54}`,
    )
    .join(" ");
  return `<svg class="sparkline" viewBox="0 0 300 80" role="img" aria-label="最近 ${samples.length} 次广播信号趋势"><path class="grid-line" d="M0 22h300M0 50h300M0 78h300"/><polyline points="${points}"/></svg>`;
}

function ago(ms: number): string {
  const seconds = Math.max(1, Math.round(ms / 1000));
  return seconds < 60 ? `${seconds} 秒前` : `${Math.floor(seconds / 60)} 分钟前`;
}

export function signalValue(observed?: Signal): string {
  if (!observed) return `—<small>dBm</small><span>尚无实时信号</span>`;
  // The backend only reports a live value for 2 seconds; a watch that advertises less often
  // (for example with its screen off) keeps its last reading instead of looking silent.
  const note = observed.ageMs
    ? `最后收到信号：${ago(observed.ageMs)}`
    : `更新于 ${escape(new Date(observed.lastSeen).toLocaleTimeString("zh-CN", { hour12: false }))}`;
  return `<em class="${observed.ageMs ? "stale" : ""}">${escape(observed.rssi)}</em><small>dBm</small><span>${note}</span>`;
}

/** What still stands between this watch and an unlock, in the order the user has to fix it. */
export function deviceReadiness(device: Device, data: Snapshot, observed?: Signal): { ok: boolean; badge: string; text: string } {
  if (!device.enabled) return { ok: false, badge: "已停用", text: "已停用，不参与解锁。可在「配置」里重新启用。" };
  if (!device.identity_configured) return { ok: false, badge: "未绑定", text: "还没保存这块手表的身份密钥，请在「设备」页的「添加手表」里配对并绑定。" };
  if (!data.credential_configured) return { ok: false, badge: "缺密码", text: "还没保存 Windows 账户密码，请在「设备」页下方填写。" };
  if (!data.backend_running) return { ok: false, badge: "后台未运行", text: "后台没有运行，不会解锁。请在「概览」点「启动后台」。" };
  if (!observed) return { ok: false, badge: "未收到信号", text: "设置齐全，但后台还没认出这块手表。戴着手表靠近电脑，几秒内应出现信号。" };
  return { ok: true, badge: "可以解锁", text: "一切就绪：锁屏后走远再回来就会解锁。" };
}

export function readinessHtml(device: Device, data: Snapshot, observed?: Signal): string {
  const ready = deviceReadiness(device, data, observed);
  return `<div class="device-head"><div class="watch-icon">${icon("devices")}</div><span class="badge ${ready.ok ? "green" : device.enabled ? "warn" : ""}">${ready.badge}</span></div>
    <h3>${escape(device.name)}</h3><p class="muted">${ready.text}</p>`;
}

export function deviceCard(device: Device, data: Snapshot, observed?: Signal): string {
  return `<article class="device-card" data-device-id="${escape(device.id)}">
    <div class="card-ready">${readinessHtml(device, data, observed)}</div>
    <div class="signal-value">${signalValue(observed)}</div>
    <div class="signal-chart">${sparkline(observed?.samples || [])}</div>
    <div class="card-meta"><span>靠近 <strong>${device.near_rssi} dBm</strong></span><span>远离 <strong>${device.far_rssi} dBm</strong></span></div>
    <div class="card-footer"><span>${device.auto_unlock_on_return ? "无感解锁" : "返回后动键鼠解锁"}</span><span class="card-actions"><button class="text-button danger" data-remove="${escape(device.id)}">移除</button><button class="text-button" data-edit="${escape(device.id)}">配置 ${icon("arrow")}</button></span></div>
  </article>`;
}

/**
 * The background is controlled for the whole session: stopping works no matter which window,
 * logon task or supervisor started it. The heartbeat is the source of truth, not window ownership.
 */
export function backendLabel(
  data: Snapshot,
  status: RuntimeStatus,
): { action: string; note: string; disabled: boolean } {
  if (data.backend_running)
    return { action: "停止后台", note: "后台正在运行 · 停止对所有窗口生效", disabled: false };
  if (status.daemon_running)
    return { action: "停止后台", note: "后台进程已启动 · 等待首次心跳", disabled: false };
  return { action: "启动后台", note: "后台未运行 · 启动后关闭窗口仍会继续运行", disabled: !status.backend_available };
}

/** Log codes stay English and stable on disk; the UI shows these names. */
const eventNames: Record<string, string> = {
  backend_started: "后台启动",
  backend_stopped: "后台停止",
  scanner_reset: "扫描器重建",
  scanner_unavailable: "扫描器中断",
  session_locked: "电脑已锁屏",
  session_unlocked: "电脑已解锁",
  session_reconciled: "会话状态核对",
  far_threshold_crossed: "越过远离阈值",
  far_before_lock: "锁屏前已离开",
  lock_watch_state: "锁屏时手表位置",
  return_detected: "检测到返回",
  return_authorization_expired: "返回授权过期",
  provider_connected: "登录界面已就绪",
  provider_disconnected: "登录界面组件断开",
  unlock_blocked: "解锁被拦下",
  display_woke: "锁屏后屏幕唤醒",
  lock_screen_input: "锁屏后检测到操作",
  legacy_cleanup_failed: "旧确认数据清理失败",
  pipe_client_connected: "登录组件已连接管道",
  pipe_session_mismatch: "登录组件会话不符",
  pipe_hello_timeout: "登录组件握手超时",
  pipe_client_dropped: "登录组件握手前断开",
  pipe_peer_rejected: "登录组件身份未通过",
  pipe_peer_not_system: "握手方不是 SYSTEM",
  pipe_peer_not_logonui: "握手方不是登录界面",
  pipe_peer_unknown: "无法识别握手方",
  pipe_create_failed: "管道创建失败",
  unlock_submitted: "已提交解锁",
  device_saved: "设备已保存",
  device_removed: "设备已解绑",
  credential_saved: "账户凭据已保存",
  credential_removed: "账户凭据已移除",
  notifications_saved: "通知设置已保存",
  notification_test: "测试通知",
  notification_failed: "通知发送失败",
  configuration_reloaded: "配置重新加载",
  settings_saved: "设置已保存",
  ui_request_failed: "操作未完成",
  lid_closed_scanning: "合盖后继续检测",
  history_cleared: "记录已清空",
  pairing_completed: "配对完成",
  pairing_failed: "配对未完成",
  pairing_advertising: "配对广播情况",
  bind_failed: "绑定未完成",
};

export const eventName = (code: string): string => eventNames[code] || code;

export type HistoryFilter = "all" | "unlock" | "config" | "backend";

const historyGroups: Record<Exclude<HistoryFilter, "all">, string[]> = {
  unlock: ["session_locked", "session_unlocked", "session_reconciled", "far_before_lock", "lock_watch_state", "far_threshold_crossed",
    "return_detected", "return_authorization_expired", "provider_connected", "provider_disconnected", "unlock_blocked", "display_woke", "lock_screen_input", "unlock_submitted"],
  config: ["device_saved", "device_removed", "credential_saved", "credential_removed",
    "notifications_saved", "settings_saved", "ui_request_failed", "notification_test", "notification_failed", "configuration_reloaded", "history_cleared",
    "pairing_completed", "pairing_failed", "pairing_advertising", "bind_failed"],
  backend: ["backend_started", "backend_stopped", "scanner_reset", "scanner_unavailable", "lid_closed_scanning",
    "pipe_client_connected", "pipe_session_mismatch", "pipe_hello_timeout", "pipe_client_dropped",
    "pipe_peer_rejected", "pipe_peer_not_system", "pipe_peer_not_logonui", "pipe_peer_unknown",
    "pipe_create_failed"],
};

export function filterHistory(entries: HistoryEntry[], filter: HistoryFilter): HistoryEntry[] {
  return filter === "all" ? entries : entries.filter((e) => historyGroups[filter].includes(e.event));
}

export function historyPage(data: Snapshot, filter: HistoryFilter): string {
  const options: [HistoryFilter, string][] = [
    ["all", "全部"], ["unlock", "锁屏与解锁"], ["config", "设备与配置"], ["backend", "后台与扫描"],
  ];
  const shown = filterHistory(data.history, filter);
  const select = `<label class="inline-select">筛选<select id="history-filter">${options
    .map(([value, label]) => `<option value="${value}" ${value === filter ? "selected" : ""}>${label}</option>`)
    .join("")}</select></label>`;
  const actions = `${select}<button class="button secondary" id="refresh-history">刷新记录</button><button class="button primary" id="copy-diagnostics">复制诊断信息</button><button class="button secondary" id="export-diagnostics">导出诊断信息</button><button class="button secondary danger" id="clear-history" ${data.history.length ? "" : "disabled"}>清空记录</button>`;
  return `${header("ACTIVITY LOG", "每次解锁，都有迹可循", `显示最近 ${data.history.length} 条中的 ${shown.length} 条。记录来自本机后端，不含密码或密钥。反馈问题时点「复制诊断信息」，直接粘贴到微信等聊天里发给开发者；需要完整内容时再点「导出诊断信息」生成文件。两者都不含密码、密钥、电脑名和设备名。`, actions)}<section class="panel" id="activity-content">${historyTable(shown, data.devices)}</section>`;
}

export function historyTable(
  entries: HistoryEntry[],
  devices: Device[],
  limit = entries.length,
): string {
  if (!entries.length)
    return `<div class="empty compact">${icon("history")}<h3>还没有操作记录</h3><p>保存配置、授权请求与后台事件将在这里显示。</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>时间</th><th>事件</th><th>设备</th><th>说明</th></tr></thead><tbody>${entries
    .slice()
    .sort((a, b) => b.at_ms - a.at_ms)
    .slice(0, limit)
    .map(
      (e) =>
        `<tr><td class="nowrap">${escape(new Date(e.at_ms).toLocaleString("zh-CN", { hour12: false }))}</td><td><span class="event-label" title="${escape(e.event)}">${escape(eventName(e.event))}</span></td><td>${escape(devices.find((d) => d.id === e.device_id)?.name || "—")}</td><td>${escape(e.detail)}</td></tr>`,
    )
    .join("")}</tbody></table></div>`;
}

export function shell(page: Page): string {
  const nav: [Page, string, string][] = [
    ["overview", "概览", "01"],
    ["devices", "设备", "02"],
    ["history", "解锁记录", "03"],
    ["notifications", "通知设置", "04"],
  ];
  return `<aside class="sidebar"><a href="#overview" class="brand"><span class="brand-logo" aria-hidden="true"></span><span>Watch Unlock<small>让靠近，成为连接</small></span></a><div class="nav-label">工作空间</div><nav aria-label="主要导航">${nav.map(([id, title, count]) => `<a href="#${id}" class="nav-item ${page === id ? "active" : ""}" ${page === id ? 'aria-current="page"' : ""}>${icon(id)}<span>${title}</span><small>${count}</small></a>`).join("")}</nav><div class="sidebar-bottom"><div class="sidebar-meta"><a class="repo-link" href="https://github.com/whyy1/watch-unlock-windows" data-link="repo" title="在 GitHub 查看源码" aria-label="在 GitHub 查看源码">${icon("github")}</a><span class="version-label">AGPL-3.0 · 不提供任何担保</span></div><button type="button" class="version-link" data-changelog>${icon("history")}<span class="version-text">更新记录</span><span class="version-dot" hidden></span></button><div class="local-status"><span class="status-dot"></span>本地处理 · 密钥加密存储</div></div></aside>
  <main id="main" tabindex="-1"><header class="topbar"><span>个人工作空间 <span class="breadcrumb">/</span> ${nav.find((n) => n[0] === page)?.[1]}</span><div class="topbar-right">${native ? '<button type="button" class="button secondary tray-button" id="hide-to-tray" title="窗口藏到右下角托盘，后台照常运行">' + icon("tray") + "缩小到托盘</button>" : '<span class="status-dot amber"></span>浏览器预览'}</div></header><div class="content"><div id="mode-banner"></div><div id="page-content"></div><footer>WATCH UNLOCK <span>公开广播只提供接近线索。当前 Apple 接入无法确认手表锁定或佩戴状态。</span></footer></div></main><div id="toast" role="status" aria-live="polite"></div><dialog id="device-dialog" aria-labelledby="device-dialog-title"></dialog><dialog id="info-dialog" aria-labelledby="info-dialog-title"></dialog>`;
}

export function header(
  eyebrow: string,
  title: string,
  description: string,
  action = "",
): string {
  return `<div class="page-header"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p>${description}</p></div>${action}</div>`;
}

/** Shown only when something stops the lock screen from unlocking. */
export function setupBanner(setup: SetupStatus | null): string {
  if (!setup) return "";
  if (!setup.running_installed)
    return "<span>当前运行的不是安装版本，后台无法解锁。请运行 setup.exe 安装，之后从开始菜单打开 Watch Unlock。</span>";
  if (!setup.provider_registered)
    return "<span>登录组件未注册，锁屏时无法解锁。请重新运行 setup.exe。</span>";
  return "";
}

export function overview(
  data: Snapshot,
  status: RuntimeStatus,
  observed: DeviceSignal[],
  setup: SetupStatus | null,
): string {
  const bound = data.devices.some((d) => d.enabled && d.identity_configured);
  const ready = data.credential_configured && bound;
  const [title, text] = ready
    ? ["配置已登记，等待后台验证", "设备与账户密码已就绪。锁屏后走远再回来即可解锁。"]
    : bound
      ? ["还差一步：保存 Windows 账户密码", "手表已经绑定，保存账户密码后，走远再回来才能解锁。<button type=\"button\" class=\"text-button\" data-goto-password>去填写密码</button>"]
      : ["准备好，连接你的第一块手表", "先在「设备」页添加手表，再保存 Windows 账户密码。"];
  return `${header("YOUR EVERYDAY CONNECTION", "每一次靠近，都有回应。", "在这里管理设备、查看信号，让解锁保持清晰可控。", '<button class="button primary" id="go-scan">' + icon("plus") + " 添加手表</button>")}
    <section class="hero"><div><span class="eyebrow" id="backend-state">${data.backend_running ? "后台运行中" : "后台尚未就绪"}</span><h2>${title}</h2><p>${text}</p><div class="hero-actions"><button class="button dark" id="daemon-toggle" ${backendLabel(data, status).disabled ? "disabled" : ""}>${backendLabel(data, status).action}</button><span class="hero-note">${backendLabel(data, status).note}</span></div><label class="toggle-row autostart-toggle"><input type="checkbox" id="autostart" ${setup?.autostart ? "checked" : ""} ${setup?.running_installed ? "" : "disabled"}/><span><strong>登录 Windows 后自动启动后台</strong><small>开机后第一次登录仍需输入密码；之后锁屏即可靠近解锁。</small></span></label><label class="toggle-row autostart-toggle"><input type="checkbox" id="lid-scan" ${data.settings?.scan_with_lid_closed ? "checked" : ""}/><span><strong>合盖时继续检测手表</strong><small>笔记本合上盖子、接外接显示器使用时打开。关闭时，合盖就停止检测，直到再次开盖，更安全。</small></span></label><p class="lock-note">本程序只负责解锁，不提供自动锁屏。如需离开时自动锁屏，请开启 Windows 自带的动态锁：设置 → 账户 → 登录选项 → 动态锁。</p></div><div class="hero-logo" aria-hidden="true"></div></section>
    <section class="stats-grid"><article class="stat"><span>已登记设备</span><strong>${data.devices.length.toString().padStart(2, "0")}</strong><small>每块设备独立配置阈值</small></article><article class="stat"><span>Windows 凭据</span><strong class="text-stat">${data.credential_configured ? "已保存" : "未设置"}</strong><small>CurrentUser DPAPI 本机加密</small></article><article class="stat"><span>通知通道</span><strong class="text-stat">${data.notifications.configured ? "已配置" : "未配置"}</strong><small>Bark 推送解锁提醒</small></article></section>
    <div class="section-heading"><div><h2>我的手表 <span>${data.devices.length}</span></h2><p>后台运行时每 2 秒更新信号。</p></div><a href="#devices">管理全部 ${icon("arrow")}</a></div>
    ${
      data.devices.length
        ? `<section class="device-grid">${data.devices
            .slice(0, 3)
            .map((d) =>
              deviceCard(
                d,
                data,
                observed.find((o) => o.deviceId === d.id),
              ),
            )
            .join("")}</section>`
        : `<section class="empty device-empty">${icon("devices")}<h3>还没有添加手表</h3><p>配对并绑定手表后，它才会参与解锁。</p><button class="button secondary" id="empty-scan">去添加手表 ${icon("arrow")}</button></section>`
    }
    <div class="section-heading"><div><h2>最近活动</h2><p>如实记录配置与授权事件。</p></div><a href="#history">查看记录 ${icon("arrow")}</a></div><section class="panel" id="activity-content">${historyTable(data.history, data.devices, 5)}</section>`;
}

/** What went wrong with a pairing window, and what the user can do about it. */
const pairingFailures: Record<string, { text: string; bluetooth?: boolean }> = {
  no_adapter: { text: "没有找到蓝牙适配器。请确认电脑有蓝牙，并且在设备管理器中已启用。" },
  radio_off: { text: "蓝牙已关闭。请在 Windows 设置中打开蓝牙后重试。", bluetooth: true },
  le_unsupported: { text: "这台电脑的蓝牙不支持低功耗蓝牙（BLE），无法与手表配对。" },
  peripheral_unsupported: {
    text: "这台电脑的蓝牙适配器不支持“外设模式”，手表搜不到这台电脑。可以换一个支持外设模式（Peripheral role）的 USB 蓝牙适配器。",
  },
  service_failed: { text: "无法开启配对服务。请关闭再打开蓝牙后重试；仍然失败的话，重启电脑。", bluetooth: true },
  advertising_aborted: { text: "配对广播被系统中断，自动重试 3 次仍未成功。请关闭再打开蓝牙后重试；仍然失败的话，在「解锁记录」页点「复制诊断信息」，粘贴发给开发者。", bluetooth: true },
  advertising_busy: { text: "蓝牙广播被占用：电脑同一时间能发出的蓝牙广播有限，Windows 的「附近共享」「手机连接」或其他蓝牙程序可能正在使用。请在“设置 → 系统 → 附近共享”里关闭附近共享，退出手机连接等程序后重试。", bluetooth: true },
  advertising_blocked: { text: "这台电脑禁止程序发出蓝牙广播，通常是公司电脑的管理策略。需要管理员放开限制，软件无法绕过。" },
  timeout: {
    text: "120 秒内没有完成配对。如果手表上看不到这台电脑，或之前配对过：先在 Windows 蓝牙设置里删除旧的配对，并在手表上忽略这台电脑，然后重试。出现过 Windows「连接失败」弹窗的，重启电脑后再配对。",
    bluetooth: true,
  },
  cancelled: { text: "配对已取消。" },
  native_process_stopped: { text: "配对进程意外退出，请重试。" },
  unavailable: { text: "配对窗口无法开启，请检查蓝牙后重试。", bluetooth: true },
};

/** Seconds the watch may sit connected without a finished pairing before the guide points at the toast. */
const toastHintAfter = 15;
/** Remaining seconds of the window when the watch first connected; null while not connected. */
let connectedAtRemaining: number | null = null;

/**
 * A numbered guide. Each step lights up from live counters; none of them is proof of identity,
 * which only the binding step establishes.
 */
export function pairingPanel(
  pairing: boolean,
  state: PairingStatus | null,
  bound = false,
  binding = false,
): string {
  const advertising = state?.advertising === "started" || state?.advertising === "limited";
  const connected = (state?.subscriptions ?? 0) > 0 || (state?.encrypted_reads ?? 0) > 0;
  // A watch bound from this pairing proves the earlier steps, whatever the window reported.
  const paired = !!state?.paired || bound;
  const failure = state?.status === "stopped" && !paired ? pairingFailures[state.reason] : undefined;
  const waitingForToast = pairing && connected && !paired && state !== null;
  if (!waitingForToast) connectedAtRemaining = null;
  else connectedAtRemaining ??= state.remaining_seconds;
  const toastMissed = waitingForToast && connectedAtRemaining !== null &&
    connectedAtRemaining - state.remaining_seconds >= toastHintAfter;
  const steps: [string, string, boolean, boolean][] = [
    ["开启配对窗口", "先点「开始配对」，手表才能搜到电脑。电脑会临时模拟成一个蓝牙配件，持续 120 秒。", pairing || paired, !pairing && !paired],
    ["在手表上选择这台电脑", "在<b>手表</b>上（不是 iPhone，也不是 Windows 设置）打开「设置 → 蓝牙」，等这台电脑出现后点它。", connected || paired, advertising && !connected && !paired],
    ["在电脑上允许配对", "电脑右下角会弹出 Windows 配对通知，点「允许」或「配对」。开着勿扰或专注模式时通知不会弹出，请打开通知中心（Win + N）查找。如果弹出 Windows 的「为设备配对 · 未知设备 · 连接失败」，说明 Windows 蓝牙卡在了上一次的配对状态：点「关闭」，在手表上忽略这台电脑，然后重启电脑再配对。", paired, connected && !paired],
    ["绑定手表", bound ? "已绑定，可以在上方的手表卡片里按实际信号调整靠近和远离阈值。"
      : binding ? "正在绑定：让手表亮屏并留在电脑旁；如果弹出 Windows 管理员确认，点「是」。最长约 30 秒。"
      : "配对完成后会自动开始绑定，读取这块手表的身份密钥。绑定时请让手表亮屏、留在电脑旁；如果弹出 Windows 管理员确认，点「是」。", bound, paired && !bound],
  ];
  const list = steps.map(([title, detail, done, active], index) =>
    `<li class="pairing-step${done ? " done" : ""}${active ? " active" : ""}"><span class="step-number" aria-hidden="true">${done ? "✓" : index + 1}</span><div><strong>${title}</strong><small>${detail}</small></div></li>`).join("");
  const status = pairing && state
    ? `<p class="pairing-meta" id="pairing-progress" aria-live="polite">剩余 ${state.remaining_seconds} 秒 · 广播${advertising ? "已开启" : "准备中"}</p>`
    : `<p class="pairing-meta" id="pairing-progress" aria-live="polite"></p>`;
  const problem = failure
    ? `<div class="pairing-failure" role="alert"><p>${failure.text}</p>${failure.bluetooth ? '<button type="button" class="button secondary" data-link="bluetooth">打开 Windows 蓝牙设置</button>' : ""}</div>`
    : toastMissed
      ? '<div class="pairing-failure" role="alert"><p>手表已经连上，但电脑还没确认配对。请看电脑右下角或通知中心（Win + N），在 Windows 配对通知里点「允许」。没有看到通知的话，检查是否开了勿扰或专注模式。如果弹出 Windows 的「为设备配对 · 未知设备 · 连接失败」，说明 Windows 蓝牙卡在了上一次的配对状态：点「关闭」，在手表上忽略这台电脑，然后重启电脑再配对。</p></div>'
      : "";
  return `<section class="panel pairing-panel"><div class="pairing-head"><div><h2>配对新的 Apple Watch</h2><p>按下面的步骤操作，配对完成后会自动绑定。</p></div><button class="button ${pairing ? "secondary" : "primary"}" id="pairing-toggle">${pairing ? "停止配对" : "开始配对"}</button></div><ol class="pairing-steps">${list}</ol>${status}${problem}</section>`;
}

export function pairedPanel(paired: PairedDevice[] | null, binding: boolean): string {
  const title = `<div class="panel-title"><div><h2>Windows 已配对设备${paired?.length ? ` <span>${paired.length}</span>` : ""}</h2><p class="muted">已在 Windows 蓝牙设置里配对过的设备，直接点「绑定此设备」，不用重新配对。</p></div>${binding ? '<span class="badge green">正在绑定…</span>' : ""}</div>`;
  if (!paired)
    return `<section class="panel" id="paired-list">${title}<p class="panel-note muted">正在读取 Windows 已配对的蓝牙设备…</p></section>`;
  if (!paired.length)
    return `<section class="panel" id="paired-list">${title}<p class="panel-note muted">尚无已配对设备。完成上方配对后，这里会显示手表名称并可直接绑定。</p></section>`;
  const rows = paired
    .map(
      (d) =>
        `<tr><td><strong>${escape(d.name || "未命名设备")}</strong></td><td class="mono">${escape(d.address)}</td><td>${d.bound ? '<span class="badge green">已绑定</span>' : '<span class="muted">未绑定</span>'}</td><td>${d.bound ? "" : `<button class="text-button" data-bind-paired="${escape(d.address)}" ${binding ? "disabled" : ""}>绑定此设备 ${icon("arrow")}</button>`}</td></tr>`,
    )
    .join("");
  return `<section class="panel" id="paired-list">${title}<div class="table-wrap"><table><thead><tr><th>名称</th><th>地址</th><th>状态</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
}

/** Everything the 添加手表 and 高级 sections of the devices page show. */
export interface AddWatchState {
  open: boolean;
  advancedOpen: boolean;
  pairing: boolean;
  pairingStatus: PairingStatus | null;
  paired: PairedDevice[] | null;
  binding: boolean;
  pairingBound: boolean;
  observed: ObservedDevice[];
  scanning: boolean;
}

/** Refreshed on its own while pairing, so typing elsewhere on the page is never wiped. */
export function addWatchContent(state: AddWatchState): string {
  return `${pairingPanel(state.pairing, state.pairingStatus, state.pairingBound, state.binding)}${pairedPanel(state.paired, state.binding)}`;
}

export function scanResults(observed: ObservedDevice[]): string {
  if (!observed.length)
    return `<div class="empty compact">${icon("signal")}<h3>等待真实蓝牙广播</h3><p>点击「开始扫描」，确保电脑蓝牙已开启且手表位于附近。</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>广播名称</th><th>当前地址</th><th>信号</th><th>识别结果</th><th></th></tr></thead><tbody>${observed
    .slice()
    .sort((a, b) => b.rssi - a.rssi)
    .map(
      (d) =>
        `<tr><td><strong>${escape(d.matched_name || d.name?.trim() || (d.apple ? "Apple 设备（未广播名称）" : "未知（未广播名称）"))}</strong><small class="cell-note">${d.apple ? "Apple 厂商广播 · 未确定设备类型" : "BLE 广播"}</small></td><td class="mono">${escape(d.address)}</td><td><span class="rssi">${icon("signal")}${d.rssi} dBm</span></td><td>${d.matched_device_id ? '<span class="badge green">命中已登记身份</span>' : '<span class="muted">未登记</span>'}</td><td><button class="text-button" data-bind="${escape(d.address)}">登记设备 ${icon("arrow")}</button></td></tr>`,
    )
    .join("")}</tbody></table></div>`;
}

/**
 * One page for adding a watch and keeping it able to unlock. Pairing and binding sit in a
 * collapsible section; scanning and manual IRK entry are tucked under 高级.
 */
export function devicesPage(data: Snapshot, observed: DeviceSignal[], add: AddWatchState): string {
  const hasIdentity = data.devices.some((device) => device.identity_configured);
  const empty = !data.devices.length;
  // A bound watch without the account password can never unlock; say so before anything else.
  const missingPassword = hasIdentity && !data.credential_configured
    ? `<div class="notice notice-warn" role="status">${icon("shield")}<div><strong>还差一步：保存 Windows 账户密码</strong><p>手表已经绑定，但还没保存账户密码，走远再回来也无法解锁。请在本页下方「账户解锁密码」里填写并保存。</p><button type="button" class="button primary" data-goto-password>去填写密码</button></div></div>`
    : "";
  const cards = empty
    ? `<div class="empty device-empty">${icon("devices")}<h3>还没有添加手表</h3><p>Apple Watch 先配对、再绑定；已经在 Windows 蓝牙设置里配对过的设备，可以直接绑定。</p><button type="button" class="button primary" id="empty-pair">${icon("plus")}配对 Apple Watch</button><button type="button" class="text-button" id="empty-bind">已在 Windows 配对过？直接绑定 ${icon("arrow")}</button></div>`
    : data.devices.map((d) => deviceCard(d, data, observed.find((o) => o.deviceId === d.id))).join("");
  return `${header("DEVICES", "每块手表，各有边界", "添加手表、查看信号、调整距离，都在这一页。Windows 登录凭据只为当前账户保存一份。", empty ? "" : `<button class="button primary" id="add-watch">${icon("plus")}添加手表</button>`)}
    ${missingPassword}
    <section class="device-grid">${cards}</section>
    <details class="fold" id="add-panel" ${add.open ? "open" : ""}><summary><div><h2>添加手表</h2><p>Apple Watch 点「开始配对」；已在 Windows 配对过的设备，在「Windows 已配对设备」里直接绑定。</p></div><span class="fold-chevron" aria-hidden="true">${icon("arrow")}</span></summary><div class="fold-body" id="add-content">${addWatchContent(add)}</div></details>
    <section class="panel credential-panel"><div><div class="eyebrow">WINDOWS CREDENTIAL</div><h2>账户解锁密码</h2><p>请填写本机登录账户的密码，不支持 PIN。密码经本机验证后加密保存。</p><p id="credential-requirement">${hasIdentity ? "设备身份已绑定，可以设置当前账户密码。" : "请先绑定设备身份，再设置当前账户密码。"}</p><span class="badge ${data.credential_configured ? "green" : ""}">${data.credential_configured ? "已保存 · 可更新" : "未设置"}</span></div><form id="credential-form"><div class="label-row"><label for="windows-password">Windows 账户密码</label><button type="button" class="text-button" id="password-help">忘记密码？</button></div><input id="windows-password" name="password" type="password" autocomplete="new-password" maxlength="1024" required ${hasIdentity ? "" : "disabled"} placeholder="仅保存在本机加密凭据库"/><div class="form-actions"><button class="button secondary" id="save-credential" type="submit" ${hasIdentity ? "" : "disabled"}>${data.credential_configured ? "更新密码" : "验证并保存"}</button>${data.credential_configured ? '<button class="text-button danger" type="button" id="clear-credential">清除凭据</button>' : ""}</div></form></section>
    <details class="fold" id="advanced-panel" ${add.advancedOpen ? "open" : ""}><summary><div><h2>高级</h2><p>排查信号时扫描附近广播；已经自己取得 IRK 时手动登记。一般用不到。</p></div><span class="fold-chevron" aria-hidden="true">${icon("arrow")}</span></summary><div class="fold-body">
      <section class="panel"><div class="panel-title"><div><h2>附近广播 <span id="scan-count">${add.observed.length}</span></h2><p class="muted">扫描持续 30 秒，只用来查看信号，不等于配对或绑定。设备可能不广播名称，Apple 广播也可能来自手机。</p></div><button class="button secondary" id="scan-toggle">${icon("scan")}${add.scanning ? "停止扫描" : "开始扫描"}</button></div><div id="scan-results">${scanResults(add.observed)}</div></section>
      <section class="panel manual-panel"><div><h2>手动登记</h2><p class="muted">只有自己取得了这块手表的 IRK 时才用。一般请用上面的「添加手表」，配对后自动绑定。</p></div><button type="button" class="button secondary" id="add-device">手动登记（已有 IRK）</button></section>
    </div></details>`;
}

export function notificationsPage(data: Snapshot): string {
  const n = data.notifications;
  return `${header("NOTIFICATIONS", "让提醒，抵达手腕", "通过 Bark 向 iPhone 推送解锁提醒。通知只作提醒，不参与解锁判断。")}
    <form id="notifications-form" class="panel settings-panel"><div class="settings-heading"><div class="setting-icon">${icon("notifications")}</div><div><h2>Bark 通知</h2><p>在 iPhone 上安装 Bark，将 App 中的设备密钥填入下方。<button type="button" class="text-button" data-link="bark">在 App Store 下载 Bark</button></p></div><span class="badge ${n.configured ? "green" : ""}">${n.configured ? "已配置密钥" : "待配置"}</span></div><div class="form-grid"><label>推送 API 地址<input name="endpoint" type="url" value="${escape(n.endpoint)}" required placeholder="https://api.day.app/push"/></label><label>Bark 设备密钥<input name="device_key" type="password" autocomplete="new-password" maxlength="256" placeholder="${n.configured ? "已保存，不用再填" : "例如 YourKey123"}"/>${n.configured ? "<small>✓ 已加密保存，不会显示。留空则沿用原密钥，更换时再填写。</small>" : ""}</label></div><p class="form-hint"><b>设备密钥</b>：Bark 示例网址 <span class="mono">https://api.day.app/<b>YourKey123</b>/推送内容</span> 里加粗的那段，区分大小写。<br/><b>推送 API 地址</b>：官方服务保持 <span class="mono">https://api.day.app/push</span>；自建服务器填自己的地址。</p><label class="toggle-row"><input name="enabled" type="checkbox" ${n.enabled ? "checked" : ""}/><span><strong>启用通知</strong><small>关闭后不发送任何通知，测试通知除外。</small></span></label><label class="toggle-row"><input name="notify_on_unlock" type="checkbox" ${n.notify_on_unlock === false ? "" : "checked"}/><span><strong>解锁后通知</strong><small>由本应用解锁后推送一条提醒；关闭后仅记入解锁记录。</small></span></label><div class="form-actions"><button type="submit" class="button primary">保存通知设置</button><button type="button" class="button secondary" id="notify-test" title="使用已保存的地址与密钥发送">发送测试通知</button><span class="muted">测试使用已保存的设置，修改后请先保存。</span></div></form>`;
}
