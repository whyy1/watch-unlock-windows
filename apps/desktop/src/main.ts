import "./style.css";
import * as bridge from "./bridge";
import { field, openDeviceDialog, secretFields } from "./dialog";
import { collectSignals, patchLive } from "./live";
import { validateDevice, validateNotifications, validatePassword } from "./validation";
import {
  addWatchContent,
  devicesPage,
  escape,
  historyPage,
  notificationsPage,
  overview,
  scanResults,
  setupBanner,
  shell,
} from "./render";
import type { AddWatchState, HistoryFilter } from "./render";
import { icon } from "./icons";
import { appVersion, findUpdate, showChangelog, showUpdate } from "./update";
import { emptySnapshot } from "./types";
import type {
  Advertisement,
  DeviceSignal,
  ObservedDevice,
  PairedDevice,
  Page,
  PairingStatus,
  RuntimeStatus,
  SetupStatus,
  Snapshot,
} from "./types";

let data: Snapshot = emptySnapshot();
let status: RuntimeStatus = { backend_available: false, daemon_running: false };
// Checked at start and after setup actions only: each check runs reg.exe and schtasks.exe.
let setup: SetupStatus | null = null;
let observed: ObservedDevice[] = [];
let signals: DeviceSignal[] = [];
let scanning = false;
let pairing = false;
let pairingStatus: PairingStatus | null = null;
let backendError = "";
let toastTimer = 0;
let refreshing = false;
let paired: PairedDevice[] | null = null;
let pairedBefore = new Set<string>();
let autoBindPending = false;
/** Set when Windows' paired list showed the new watch before the pairing window reported it. */
let pairedByWindows = false;
let lastPairedCheck = 0;
/** Set by "去填写密码" so the next page render focuses the account password field. */
let passwordFocusPending = false;
/** A watch was bound after the current pairing window opened. */
let boundThisPairing = false;
let version = "";
/** An update found at start; the sidebar button then opens it instead of the changelog. */
let pendingUpdate: Awaited<ReturnType<typeof findUpdate>> = null;
const seenKey = "watch-unlock.changelog-seen";

function changelogSeen(): boolean {
  try { return localStorage.getItem(seenKey) === version; } catch { return true; }
}
let binding = false;
/** Ticks the elapsed time in the binding dialog. */
let bindingTimer = 0;
let historyFilter: HistoryFilter = "all";
/** The user's choice for the 添加手表 section; null until they open or close it. */
let addOpen: boolean | null = null;
let advancedOpen = false;

const pages: Page[] = [
  "overview",
  "devices",
  "history",
  "notifications",
];
const currentPage = (): Page =>
  pages.find((p) => p === location.hash.slice(1)) || "overview";

/** Open while there is nothing to show yet or a pairing or binding is running, unless the user chose. */
function addState(): AddWatchState {
  return {
    open: pairing || binding || (addOpen ?? !data.devices.length),
    advancedOpen,
    pairing,
    pairingStatus,
    paired,
    binding,
    pairingBound: pairingBound(),
    observed,
    scanning,
  };
}

/** Shows the 添加手表 section, from any page, and scrolls to `target` inside it. */
function openAddWatch(target = "#add-panel"): void {
  addOpen = true;
  if (currentPage() !== "devices") {
    pendingScroll = target;
    location.hash = "devices";
    return;
  }
  const panel = document.querySelector<HTMLDetailsElement>("#add-panel");
  if (panel) panel.open = true;
  document.querySelector<HTMLElement>(target)?.scrollIntoView({ behavior: "smooth", block: "start" });
}
/** Where to scroll after the next page change. */
let pendingScroll = "";

function toast(message: string): void {
  const element = document.querySelector<HTMLDivElement>("#toast")!;
  element.textContent = message;
  element.title = "点击复制这条提示";
  // Users often send these messages on; a click copies the text instead of a screenshot.
  element.onclick = () => {
    void navigator.clipboard.writeText(message).then(
      () => { element.textContent = "已复制到剪贴板。"; },
      () => undefined,
    );
  };
  element.classList.add("visible");
  window.clearTimeout(toastTimer);
  // Long guidance, such as the wrong-password steps, needs longer than a short notice.
  toastTimer = window.setTimeout(
    () => element.classList.remove("visible"),
    Math.min(20000, Math.max(6000, message.length * 150)),
  );
}

async function act(action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (error) {
    toast(error instanceof Error ? error.message : "操作未完成，请检查后端。");
  }
}

async function refresh(): Promise<void> {
  const result = await Promise.allSettled([
    bridge.snapshot(),
    bridge.runtime(),
  ]);
  if (result[0].status === "fulfilled") {
    data = result[0].value;
    signals = collectSignals(data, signals, observed);
    backendError = "";
  } else {
    backendError = "尚未连接本地后端。请构建 watchd，并检查固定后端路径。";
    data = { ...data, backend_running: false, runtime: { running: false } };
    signals = [];
  }
  status = result[1].status === "fulfilled"
    ? result[1].value : { backend_available: false, daemon_running: false };
}

/** Shows only what currently stops unlocking; hidden when everything is in place. */
function renderBanner(): void {
  const banner = document.querySelector<HTMLDivElement>("#mode-banner");
  if (!banner) return;
  const html = !bridge.native
    ? "<span>浏览器界面预览：不连接蓝牙，不保存设置。请运行桌面应用使用真实功能。</span>"
    : backendError ? `<span>${backendError}</span>` : setupBanner(setup);
  if (banner.dataset.html === html) return;
  banner.dataset.html = html;
  banner.className = "mode-banner";
  banner.hidden = !html;
  banner.innerHTML = html;
}

function render(): void {
  const page = currentPage();
  document.querySelector<HTMLDivElement>("#app")!.innerHTML = shell(page);
  renderBanner();
  const content = document.querySelector<HTMLDivElement>("#page-content")!;
  if (page === "overview") content.innerHTML = overview(data, status, signals, setup);
  if (page === "devices") content.innerHTML = devicesPage(data, signals, addState());
  if (page === "history") content.innerHTML = historyPage(data, historyFilter);
  if (page === "notifications") content.innerHTML = notificationsPage(data);
  bind();
}

function bindChangelog(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-changelog]").forEach((button) => {
    const text = button.querySelector<HTMLElement>(".version-text");
    const dot = button.querySelector<HTMLElement>(".version-dot");
    if (text && pendingUpdate) text.textContent = `有新版本 v${pendingUpdate.version}`;
    else if (text && version) text.textContent = `v${version} · 更新记录`;
    // A dot until this version's notes are opened, or while an update waits.
    if (dot) dot.hidden = !pendingUpdate && (!version || changelogSeen());
    button.classList.toggle("has-update", !!pendingUpdate);
    button.onclick = () => {
      if (pendingUpdate) { showUpdate(pendingUpdate, toast); return; }
      try { localStorage.setItem(seenKey, version); } catch { /* the dot just stays */ }
      if (dot) dot.hidden = true;
      void showChangelog(toast);
    };
  });
}

function bind(): void {
  bindChangelog();
  document.querySelectorAll<HTMLElement>("[data-link]").forEach((element) => {
    element.onclick = (event) => {
      event.preventDefault();
      const link = element.dataset.link;
      if (link === "repo" || link === "bark" || link === "bluetooth") void act(() => bridge.openLink(link));
    };
  });
  document
    .querySelectorAll<HTMLButtonElement>("#go-scan, #empty-scan, #add-watch")
    .forEach((b) => {
      b.onclick = () => openAddWatch();
    });
  document.querySelector<HTMLButtonElement>("#empty-bind")?.addEventListener("click", () => openAddWatch("#paired-list"));
  document.querySelector<HTMLButtonElement>("#empty-pair")?.addEventListener("click", () => {
    openAddWatch("#add-content");
    if (!pairing) document.querySelector<HTMLButtonElement>("#pairing-toggle")?.click();
  });
  // Remember only what the user clicks; a section rendered open also fires "toggle".
  document.querySelector<HTMLElement>("#add-panel > summary")?.addEventListener("click", () => {
    addOpen = !document.querySelector<HTMLDetailsElement>("#add-panel")!.open;
  });
  document.querySelector<HTMLElement>("#advanced-panel > summary")?.addEventListener("click", () => {
    advancedOpen = !document.querySelector<HTMLDetailsElement>("#advanced-panel")!.open;
  });
  document
    .querySelector<HTMLButtonElement>("#add-device")
    ?.addEventListener("click", () => showDevice());
  document.querySelectorAll<HTMLButtonElement>("[data-edit]").forEach((b) => {
    b.onclick = () => showDevice(b.dataset.edit);
  });
  document.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((b) => {
    b.onclick = () => removeDevice(b.dataset.remove || "");
  });
  bindScanRows();
  bindAddContent();
  document.querySelector<HTMLButtonElement>("#scan-toggle")?.addEventListener(
    "click",
    () =>
      void act(async () => {
        const shouldStart = !scanning;
        await bridge.scan(shouldStart);
        scanning = shouldStart;
        if (shouldStart) observed = [];
        updateScanPanel();
      }),
  );
  document.querySelector<HTMLInputElement>("#autostart")?.addEventListener("change", (event) => {
    const input = event.currentTarget as HTMLInputElement;
    const enabled = input.checked;
    input.disabled = true;
    void act(async () => {
      try {
        setup = await bridge.setAutostart(enabled);
        toast(enabled ? "已开启：以后每次登录 Windows 都会自动启动后台。" : "已关闭开机自启；需要时请手动启动后台。");
      } finally {
        render();
      }
    });
  });
  document.querySelector<HTMLInputElement>("#lid-scan")?.addEventListener("change", (event) => {
    const input = event.currentTarget as HTMLInputElement;
    const enabled = input.checked;
    input.disabled = true;
    void act(async () => {
      try {
        data = await bridge.request<Snapshot>({ op: "save_settings", scan_with_lid_closed: enabled });
        toast(enabled ? "已开启：合盖后会继续检测手表。" : "已关闭：合盖后停止检测手表，开盖后恢复。");
      } finally {
        render();
      }
    });
  });
  document.querySelector<HTMLButtonElement>("#daemon-toggle")?.addEventListener(
    "click",
    () =>
      void act(async () => {
        // The heartbeat reflects any running background, including one started at logon.
        const stopping = data.backend_running || status.daemon_running;
        status = await bridge.daemon(!stopping);
        await refresh();
        render();
        toast(
          stopping
            ? "已请求停止后台，对所有窗口与开机任务启动的后台都生效。"
            : "后台已启动，关闭窗口后仍会继续运行。几秒后可看到心跳。",
        );
      }),
  );
  document.querySelectorAll<HTMLButtonElement>("[data-goto-password]").forEach((button) => {
    button.onclick = goToPassword;
  });
  document
    .querySelector<HTMLButtonElement>("#copy-diagnostics")
    ?.addEventListener("click", () => void act(copyDiagnostics));
  document
    .querySelector<HTMLButtonElement>("#export-diagnostics")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          const path = await bridge.exportDiagnostics();
          toast(`诊断信息已保存到“下载”文件夹：${path.split("\\").pop()}`);
        }),
    );
  document
    .querySelector<HTMLButtonElement>("#refresh-history")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          await refresh();
          render();
        }),
    );
  document
    .querySelector<HTMLSelectElement>("#history-filter")
    ?.addEventListener("change", (event) => {
      historyFilter = (event.target as HTMLSelectElement).value as HistoryFilter;
      render();
    });
  document
    .querySelector<HTMLButtonElement>("#clear-history")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          if (!confirm("清空全部解锁记录？清空操作本身会留下一条记录。")) return;
          data = await bridge.request<Snapshot>({ op: "clear_history" });
          render();
          toast("解锁记录已清空。");
        }),
    );
  document
    .querySelector<HTMLButtonElement>("#notify-test")
    ?.addEventListener(
      "click",
      (event) =>
        void act(async () => {
          const button = event.currentTarget as HTMLButtonElement;
          button.disabled = true;
          try {
            data = await bridge.request<Snapshot>({ op: "notify_test" });
            toast("测试通知已被 Bark 接受，请检查手机或手表。");
          } finally {
            button.disabled = false;
          }
        }),
    );
  document
    .querySelector<HTMLFormElement>("#credential-form")
    ?.addEventListener("submit", saveCredential);
  document.querySelector<HTMLButtonElement>("#password-help")?.addEventListener("click", showPasswordHelp);
  document
    .querySelector<HTMLButtonElement>("#clear-credential")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          if (!confirm("清除当前 Windows 账户的已保存解锁凭据？")) return;
          await bridge.request({ op: "clear_credential" });
          await refresh();
          render();
          toast("已清除保存的凭据。");
        }),
    );
  document
    .querySelector<HTMLFormElement>("#notifications-form")
    ?.addEventListener("submit", saveNotifications);
}

/**
 * Binds the one watch that this pairing window added. With several new entries the user picks
 * one in the paired list instead, so a nearby stranger's device is never bound by guess.
 */
function autoBindNewWatch(): void {
  if (!autoBindPending || binding) return;
  const fresh = freshPaired();
  if (!fresh.length) return;
  autoBindPending = false;
  if (fresh.length === 1) void bindPairedDevice(fresh[0].address);
  else toast("配对完成。请在“Windows 已配对设备”中选择你的手表并点击绑定。");
}

/** Step 4 of the guide: the watch from this pairing is bound, here or by an earlier bind of the new entry. */
function pairingBound(): boolean {
  return boundThisPairing
    || (pairingStatus !== null && (paired ?? []).some((device) => device.bound && !pairedBefore.has(device.address)));
}

/** Unbound devices Windows paired after this pairing window opened. */
function freshPaired(): PairedDevice[] {
  return (paired ?? []).filter((device) => !device.bound && !pairedBefore.has(device.address));
}

/**
 * Windows' own paired list is the fallback pairing signal: a watch can bond without the
 * encrypted read the pairing window watches for. A new entry ends the window early.
 */
function checkPairedList(event: PairingStatus): void {
  const connected = event.subscriptions > 0 || event.encrypted_reads > 0;
  const due = connected && Date.now() - lastPairedCheck >= 3000;
  if (!event.paired && event.status !== "stopped" && !due) return;
  lastPairedCheck = Date.now();
  void loadPaired().then(() => {
    if (!pairedByWindows && freshPaired().length) {
      pairedByWindows = true;
      if (pairingStatus) pairingStatus = { ...pairingStatus, paired: true };
      if (pairing) void bridge.pair(false).catch(() => undefined);
    }
    refreshAddPanel();
    autoBindNewWatch();
    // A watch Windows paired earlier never shows up as new; it only needs binding.
    if (event.status === "stopped" && !pairedByWindows && event.reason !== "cancelled"
      && (paired ?? []).some((device) => !device.bound))
      toast("如果你的手表已经在下方“Windows 已配对设备”里，直接点「绑定此设备」即可，不用重新配对。");
  });
}

/** Reads Windows' paired list. Failure shows an empty list instead of stale names. */
async function loadPaired(): Promise<void> {
  try {
    paired = await bridge.pairedDevices();
  } catch {
    paired = [];
    toast("未能读取 Windows 已配对设备，请检查蓝牙与后端记录。");
  }
}

/**
 * Redraws only the 添加手表 section. Pairing events arrive every second; a full render would
 * wipe a password being typed further down the page.
 */
function refreshAddPanel(): void {
  if (currentPage() !== "devices") return;
  const content = document.querySelector<HTMLElement>("#add-content");
  if (!content) return;
  content.innerHTML = addWatchContent(addState());
  bindAddContent();
}

function bindAddContent(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-bind-paired]").forEach((b) => {
    b.onclick = () => void bindPairedDevice(b.dataset.bindPaired || "");
  });
  const toggle = document.querySelector<HTMLButtonElement>("#pairing-toggle");
  if (toggle)
    toggle.onclick = () =>
      void act(async () => {
        const shouldStart = !pairing;
        if (shouldStart) {
          pairingStatus = null;
          // Remember who was already paired, so only the watch paired now is bound automatically.
          pairedBefore = new Set((paired ?? []).map((device) => device.address));
          autoBindPending = true;
          pairedByWindows = false;
          boundThisPairing = false;
        }
        await bridge.pair(shouldStart);
        pairing = shouldStart;
        refreshAddPanel();
      });
}

/** The 高级 scan list and its button, without touching the rest of the page. */
function updateScanPanel(): void {
  const button = document.querySelector<HTMLButtonElement>("#scan-toggle");
  if (button) button.innerHTML = `${icon("scan")}${scanning ? "停止扫描" : "开始扫描"}`;
  const results = document.querySelector<HTMLDivElement>("#scan-results");
  if (results) {
    results.innerHTML = scanResults(observed);
    bindScanRows();
  }
  const count = document.querySelector<HTMLElement>("#scan-count");
  if (count) count.textContent = String(observed.length);
}

/**
 * Elevated, one-time identity read. The UAC prompt and the 30 s verification scan both happen
 * in the backend; a dialog stays up until the request returns and then shows the outcome.
 */
async function bindPairedDevice(address: string): Promise<void> {
  const target = paired?.find((d) => d.address === address);
  if (!target || binding) return;
  binding = true;
  // Quotes are rejected by the request validator; the name is editable afterwards.
  const name = (target.name || "").replace(/["\u0000-\u001f]/g, "").trim() || "Apple Watch";
  showBinding(name);
  refreshAddPanel();
  let boundId: string | null = null;
  let failure = "";
  try {
    await bridge.bindPaired(address, name);
    await refresh();
    boundId = data.devices.find((d) => d.address === address)?.id ?? null;
    if (boundId && pairingStatus) boundThisPairing = true;
  } catch (error) {
    failure = error instanceof Error ? error.message : "绑定未完成，请重试。";
  } finally {
    binding = false;
    window.clearInterval(bindingTimer);
  }
  await loadPaired();
  render();
  if (boundId) showBound(boundId);
  else showBindFailed(address, name, failure || "绑定未完成，请重试。");
}

function infoDialog(): HTMLDialogElement {
  return document.querySelector<HTMLDialogElement>("#info-dialog")!;
}

/** Opens the dialog unless it is already up, as when the binding dialog turns into its result. */
function showInfo(dialog: HTMLDialogElement): void {
  dialog.querySelectorAll<HTMLButtonElement>("[data-close-dialog]").forEach((button) => {
    button.onclick = () => dialog.close();
  });
  if (!dialog.open) dialog.showModal();
}

/**
 * The backend reports no stages, so this shows what the user must do and the time spent, not a
 * made-up progress bar. Closing it only hides it: the elevated process cannot be stopped midway.
 */
function showBinding(name: string): void {
  const dialog = infoDialog();
  const started = Date.now();
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">BINDING</div><h2 id="info-dialog-title">正在绑定「${escape(name)}」</h2></div><button type="button" class="close-button" data-close-dialog aria-label="先收起，绑定会继续">×</button></div>
    <div class="binding-progress"><span class="binding-spinner" aria-hidden="true"></span><div><strong>正在读取并验证手表身份</strong><small id="binding-elapsed">已用 0 秒 · 验证最长约 30 秒</small></div></div>
    <ol class="binding-tips">
      <li><strong>抬起手腕，让手表亮屏</strong>，放在电脑旁边。手表息屏时广播变少，验证可能超时。</li>
      <li>如果弹出 Windows 管理员确认，点「是」。</li>
      <li>验证期间请不要走开。</li>
    </ol>
    <p class="form-hint">绑定会读取 Windows 配对时保存的手表密钥，再用手表的实时广播核对。关掉这个窗口不会中断绑定，结束后会提示结果。</p>`;
  window.clearInterval(bindingTimer);
  bindingTimer = window.setInterval(() => {
    const elapsed = document.querySelector<HTMLElement>("#binding-elapsed");
    if (elapsed) elapsed.textContent = `已用 ${Math.round((Date.now() - started) / 1000)} 秒 · 验证最长约 30 秒`;
  }, 1000);
  showInfo(dialog);
}

function showBindFailed(address: string, name: string, message: string): void {
  const dialog = infoDialog();
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">NOT BOUND</div><h2 id="info-dialog-title">「${escape(name)}」没有绑定成功</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭">×</button></div>
    <div class="pairing-failure" role="alert"><p>${escape(message)}</p></div>
    <p class="form-hint">重试前请抬腕让手表亮屏，并放在电脑旁边。</p>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button secondary" data-close-dialog>关闭</button><button type="button" class="button primary" id="bind-retry">重试</button></div>`;
  dialog.querySelector<HTMLButtonElement>("#bind-retry")!.onclick = () => void bindPairedDevice(address);
  showInfo(dialog);
}

/** After binding: say what is still missing, so the user is not left wondering. */
function showBound(id: string): void {
  const dialog = infoDialog();
  const ready = data.credential_configured;
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">PAIRED</div><h2 id="info-dialog-title">手表已绑定</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭">×</button></div>
    <p class="form-hint" role="status">${ready
      ? "账户密码已保存，现在锁屏后走远再回来就能解锁。可以按实际信号调整靠近和远离距离。"
      : "还差一步：保存 Windows 账户密码。没有密码时，手表走远再回来也无法解锁。"}</p>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button secondary" id="bound-adjust">调整距离</button><button type="button" class="button primary" id="bound-next">${ready ? "查看设备" : "去填写密码"}</button></div>`;
  dialog.querySelector<HTMLButtonElement>("#bound-adjust")!.onclick = () => { dialog.close(); showDevice(id); };
  dialog.querySelector<HTMLButtonElement>("#bound-next")!.onclick = () => {
    dialog.close();
    if (ready) location.hash = "devices";
    else goToPassword();
  };
  showInfo(dialog);
}

/** Opens the 设备 page with the account password field focused. */
function goToPassword(): void {
  if (currentPage() === "devices") { focusPassword(); return; }
  passwordFocusPending = true;
  location.hash = "devices";
}

/**
 * The report takes a few seconds; handing the clipboard a pending item keeps the click's user
 * activation, which a plain writeText after the wait would have lost.
 */
async function copyDiagnostics(): Promise<void> {
  const summary = bridge.diagnosticsSummary();
  try {
    await navigator.clipboard.write([new ClipboardItem({
      "text/plain": summary.then((text) => new Blob([text], { type: "text/plain" })),
    })]);
    toast("诊断信息已复制，直接粘贴到微信等聊天里发给开发者即可。");
  } catch {
    // Fall back to a selectable copy the user can take with Ctrl + C.
    showSummary(await summary);
  }
}

function showPasswordHelp(): void {
  const dialog = infoDialog();
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">ACCOUNT PASSWORD</div><h2 id="info-dialog-title">重置账户密码</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭">×</button></div>
    <p class="form-hint">此处需填写本机登录账户的密码，不支持 PIN。如忘记密码，可在锁屏界面重置：</p>
    <ol class="binding-tips">
      <li>按 Win + L 锁屏，在登录选项中选择密码登录。</li>
      <li>输入一次错误密码后，点击「重置密码」，按提示完成重置。</li>
      <li>重置后的新密码即为此处应填写的密码。</li>
    </ol>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button primary" data-close-dialog>确定</button></div>`;
  showInfo(dialog);
}

function showSummary(text: string): void {
  const dialog = document.querySelector<HTMLDialogElement>("#info-dialog")!;
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">DIAGNOSTICS</div><h2 id="info-dialog-title">复制诊断信息</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭对话框">×</button></div>
    <p class="form-hint">没能自动复制。下面的内容已全部选中，按 Ctrl + C 复制，再粘贴发给开发者。</p>
    <textarea class="diagnostics-text" readonly rows="14">${escape(text)}</textarea>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button primary" data-close-dialog>关闭</button></div>`;
  dialog.querySelectorAll<HTMLButtonElement>("[data-close-dialog]").forEach((button) => {
    button.onclick = () => dialog.close();
  });
  dialog.showModal();
  dialog.querySelector<HTMLTextAreaElement>("textarea")?.select();
}

function focusPassword(): void {
  const input = document.querySelector<HTMLInputElement>("#windows-password");
  input?.scrollIntoView({ block: "center" });
  input?.focus();
}

function bindScanRows(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-bind]").forEach((b) => {
    b.onclick = () =>
      showDevice(
        undefined,
        observed.find((o) => o.address === b.dataset.bind)?.name,
      );
  });
}

function showDevice(id?: string, name?: string | null): void {
  const device = data.devices.find((d) => d.id === id);
  const dialog = openDeviceDialog(device, name);
  dialog
    .querySelector<HTMLFormElement>("#device-form")!
    .addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      void act(async () => {
        const values = new FormData(form);
        const near = Number(field(values, "near_rssi"));
        const far = Number(field(values, "far_rssi"));
        try {
          validateDevice(field(values, "name"), near, far, field(values, "irk"),
            field(values, "irk_blob_path"), Boolean(device?.identity_configured));
          await bridge.request({
            op: "save_device",
            device: {
              ...(device ? { id: device.id } : {}),
              name: field(values, "name"),
              adapter: "apple-ble",
              ...(field(values, "irk") ? { irk: field(values, "irk") } : {}),
              ...(field(values, "irk_blob_path") ? { irk_blob_path: field(values, "irk_blob_path") } : {}),
              near_rssi: near,
              far_rssi: far,
              return_window_seconds: Number(field(values, "return_window_seconds")),
              enabled: values.has("enabled"),
              auto_unlock_on_return: values.has("auto_unlock_on_return"),
            },
          });
        } finally {
          secretFields(form);
        }
        dialog.close();
        await refresh();
        render();
        toast("设备配置已保存；这不代表已经完成系统配对。");
      });
    });
  dialog.querySelector<HTMLButtonElement>("#remove-device")?.addEventListener(
    "click",
    () => removeDevice(id || "", dialog),
  );
}

function removeDevice(id: string, dialog?: HTMLDialogElement): void {
  const device = data.devices.find((d) => d.id === id);
  if (!device) return;
  void act(async () => {
    if (!confirm(`移除「${device.name}」及其保存的身份材料？移除后要重新绑定才能解锁。`)) return;
    await bridge.request({ op: "remove_device", id });
    dialog?.close();
    await refresh();
    render();
    toast("设备已移除。");
  });
}

function saveCredential(event: SubmitEvent): void {
  event.preventDefault();
  const form = event.currentTarget as HTMLFormElement;
  void act(async () => {
    try {
      const input = form.querySelector<HTMLInputElement>('[name="password"]')!;
      validatePassword(input.value, data.devices.some((device) => device.identity_configured));
      await bridge.request({ op: "save_credential", password: input.value });
    } finally {
      secretFields(form);
    }
    await refresh();
    render();
    toast("账户密码已验证并加密保存。");
  });
}

function saveNotifications(event: SubmitEvent): void {
  event.preventDefault();
  const form = event.currentTarget as HTMLFormElement;
  void act(async () => {
    const values = new FormData(form);
    const endpoint = field(values, "endpoint");
    try {
      validateNotifications(endpoint, field(values, "device_key"));
      await bridge.request({
        op: "save_notifications",
        endpoint,
        enabled: values.has("enabled"),
        notify_on_unlock: values.has("notify_on_unlock"),
        ...(field(values, "device_key")
          ? { device_key: field(values, "device_key") }
          : {}),
      });
    } finally {
      secretFields(form);
    }
    await refresh();
    render();
    toast("通知设置已保存；可用“发送测试通知”验证。");
  });
}

function receive(advertisement: Advertisement): void {
  if (!Number.isFinite(advertisement.rssi) || !advertisement.address) return;
  const sameDevice = (candidate: ObservedDevice): boolean =>
    candidate.address === advertisement.address ||
    Boolean(
      advertisement.matched_device_id &&
      candidate.matched_device_id === advertisement.matched_device_id,
    );
  const previous = observed.find(sameDevice);
  const next: ObservedDevice = {
    ...advertisement,
    samples: [...(previous?.samples || []), advertisement.rssi].slice(-30),
    lastSeen: Date.now(),
  };
  observed = [...observed.filter((o) => !sameDevice(o)), next].slice(-200);
  if (currentPage() === "devices") updateScanPanel();
  if (currentPage() === "overview" || currentPage() === "devices") {
    signals = collectSignals(data, signals, observed);
    patchLive(data, status, signals, currentPage(), showDevice, removeDevice);
  }
}

/** The former 附近扫描 page is now the 添加手表 section of the 设备 page. */
function redirectOldScanLink(): void {
  if (location.hash !== "#scan") return;
  addOpen = true;
  history.replaceState(null, "", "#devices");
}

window.addEventListener("hashchange", () => {
  redirectOldScanLink();
  render();
  document.querySelector<HTMLElement>("#main")?.focus();
  if (passwordFocusPending) { passwordFocusPending = false; focusPassword(); }
  if (pendingScroll) {
    const target = pendingScroll;
    pendingScroll = "";
    document.querySelector<HTMLElement>(target)?.scrollIntoView({ block: "start" });
  }
  if (currentPage() === "devices") void loadPaired().then(refreshAddPanel);
});
window.addEventListener("beforeunload", () => {
  document
    .querySelectorAll<HTMLInputElement>('input[type="password"]')
    .forEach((input) => {
      input.value = "";
    });
});
redirectOldScanLink();
// Known before the first paint, so the banner and autostart switch render correctly.
setup = await bridge.setupStatus().catch(() => null);
render();
await refresh();
// Right after setup.exe nobody has logged on since, so the logon entry has not run yet. The
// installer kills the background without a final status write, so `backend_running` can still
// look fresh here; the supervisor is single-instance, so starting it again is harmless.
if (setup?.running_installed && setup.autostart && !status.daemon_running) {
  status = await bridge.daemon(true).catch(() => status);
  await refresh();
}
version = await appVersion();
render();
// Only the installed copy updates itself; a failed check stays silent.
if (setup?.running_installed)
  void findUpdate().then((update) => {
    if (!update) return;
    pendingUpdate = update;
    bindChangelog();
    showUpdate(update, toast);
  });
void loadPaired().then(refreshAddPanel);
await bridge.subscribe(
  receive,
  (scanStatus) => {
    scanning = scanStatus === "running";
    updateScanPanel();
    if (scanStatus === "failed")
      toast("扫描未完成，请检查蓝牙适配器与后端记录。");
  },
  (event) => {
    pairingStatus = pairedByWindows ? { ...event, paired: true } : event;
    pairing = event.status !== "stopped";
    // A completed Windows pairing or a closed window can change the paired list.
    checkPairedList(event);
    refreshAddPanel();
  },
  () => {
    pairing = false;
    toast(
      "配对进程意外结束，请重试。仍然失败的话，在「解锁记录」页点「复制诊断信息」，粘贴发给开发者。",
    );
  },
);

if (bridge.native)
  window.setInterval(() => {
    if (refreshing) return;
    refreshing = true;
    void refresh()
      .then(() => {
        patchLive(data, status, signals, currentPage(), showDevice, removeDevice);
        renderBanner();
      })
      .finally(() => {
        refreshing = false;
      });
  }, 2000);
