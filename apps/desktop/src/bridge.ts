import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  Advertisement,
  PairedDevice,
  PairingStatus,
  RuntimeStatus,
  SetupStatus,
  Snapshot,
} from "./types";
import { emptySnapshot } from "./types";

export const native = isTauri();

interface Envelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

export async function request<T = unknown>(
  request: Record<string, unknown>,
): Promise<T> {
  if (!native)
    throw new Error("浏览器为界面预览；保存和硬件操作需要桌面应用。");
  const response = await invoke<Envelope<T>>("backend_request", { request });
  if (!response.ok)
    throw new Error(response.error || "后端未完成操作，请检查运行状态。");
  return response.data as T;
}

export async function snapshot(): Promise<Snapshot> {
  return native ? request<Snapshot>({ op: "snapshot" }) : emptySnapshot();
}

export async function runtime(): Promise<RuntimeStatus> {
  return native
    ? invoke<RuntimeStatus>("runtime_status")
    : { backend_available: false, daemon_running: false };
}

export async function scan(start: boolean): Promise<void> {
  if (!native) throw new Error("请在桌面应用中使用真实蓝牙扫描。");
  await invoke(start ? "start_scan" : "stop_scan");
}

export async function pairedDevices(): Promise<PairedDevice[]> {
  if (!native) return [];
  const result = await request<{ devices: PairedDevice[] }>({ op: "paired_devices" });
  return result.devices;
}

/** Starts an elevated, one-time IRK read for a Windows-paired watch. Slow: UAC plus a 30 s scan. */
export async function bindPaired(address: string, name: string): Promise<void> {
  if (!native) throw new Error("绑定仅能在桌面应用中操作。");
  await request({ op: "bind_paired", address, name });
}

export async function daemon(start: boolean): Promise<RuntimeStatus> {
  if (!native) throw new Error("请在桌面应用中管理后台。");
  try { return await invoke<RuntimeStatus>(start ? "start_daemon" : "stop_daemon"); }
  catch (error) {
    throw new Error(error === "use_installed_copy"
      ? "本机已安装 Watch Unlock，请从开始菜单打开它再启动后台。"
      : "后台操作失败，请检查安装目录。");
  }
}

export async function pair(start: boolean): Promise<void> {
  if (!native) throw new Error("Windows 配对仅能在桌面应用中操作。");
  await invoke(start ? "start_pairing" : "stop_pairing");
}

export type Link = "repo" | "bark" | "bluetooth";

export async function openLink(link: Link): Promise<void> {
  if (!native) throw new Error("请在桌面应用中打开链接。");
  try { await invoke("open_link", { link }); }
  catch { throw new Error("未能打开系统浏览器，请检查默认浏览器设置。"); }
}

export async function subscribe(
  onAdvertisement: (advertisement: Advertisement) => void,
  onStatus: (status: string) => void,
  onPairing: (status: PairingStatus) => void,
  onPairingError: () => void,
): Promise<() => void> {
  if (!native) return () => {};
  const stopAdvertisement = await listen<Advertisement>("advertisement", (e) =>
    onAdvertisement(e.payload),
  );
  const stopStatus = await listen<string>("scan-status", (e) =>
    onStatus(e.payload),
  );
  const stopPairing = await listen<PairingStatus>("pairing-status", (e) =>
    onPairing(e.payload),
  );
  const stopPairingError = await listen<string>(
    "pairing-error",
    onPairingError,
  );
  return () => {
    stopAdvertisement();
    stopStatus();
    stopPairing();
    stopPairingError();
  };
}

export async function setupStatus(): Promise<SetupStatus | null> {
  return native ? invoke<SetupStatus>("setup_status") : null;
}

/** Hides the window to the notification area, as minimizing does. */
export async function hideToTray(): Promise<void> {
  if (native) await invoke("hide_to_tray");
}

/** Writes the diagnostics file into Downloads and returns its path. */
export async function exportDiagnostics(): Promise<string> {
  if (!native) throw new Error("浏览器预览不能导出诊断信息。");
  try { return await invoke<string>("export_diagnostics"); }
  catch { throw new Error("导出失败，请确认“下载”文件夹可以写入。"); }
}

export async function diagnosticsSummary(): Promise<string> {
  if (!native) throw new Error("浏览器预览不能读取诊断信息。");
  try { return await invoke<string>("diagnostics_summary"); }
  catch { throw new Error("读取诊断信息失败，请改用「导出诊断信息」。"); }
}

export async function setAutostart(enabled: boolean): Promise<SetupStatus> {
  try { return await invoke<SetupStatus>("set_autostart", { enabled }); }
  catch (error) {
    if (error === "autostart_timeout")
      throw new Error("开机自启设置超时，修改启动项可能被安全软件拦截了。请在安全软件里允许 Watch Unlock 修改启动项，再重试。");
    if (error === "autostart_failed")
      throw new Error("开机自启设置失败，修改启动项可能被安全软件拦截了。请在安全软件里允许 Watch Unlock 修改启动项，再重试。");
    throw new Error("开机自启设置失败，请确认已安装到本机。");
  }
}
