//! Plain-text report for support. Secrets are never read: only whether each one is stored.
//! Nothing identifies the machine or the watch: devices appear as "设备 N" by list position, and
//! only the notification server's host name is kept.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use serde_json::{json, Value};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

use crate::registry::{self, Device};

const EVENTS: usize = 500;
const SUPERVISOR_LINES: usize = 200;
/// Stays under the window's 256 KiB response limit after JSON escaping.
const MAX_TEXT: usize = 200 * 1024;
/// 100 ns intervals between 1601-01-01 (FILETIME) and 1970-01-01 (Unix).
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// `{"text": report, "stamp": "YYYYMMDD-HHMMSS"}` in local time.
pub fn report() -> Result<Value> {
    let now = crate::audit::epoch_ms();
    let mut text = String::new();
    section(&mut text, "Windows");
    line(&mut text, "版本", &windows_version());
    line(&mut text, "生成时间", &local_time(now).unwrap_or_else(|| "未知".into()));

    section(&mut text, "权限");
    // This process inherits the window's elevation, so it tells whether the app runs as administrator.
    let elevated = crate::bind::is_elevated().ok().map_or("未知", |value| yes_no(value, "是", "否"));
    line(&mut text, "应用以管理员身份运行", elevated);
    line(&mut text, "数据目录所有者", data_owner());

    let devices = registry::load_devices().unwrap_or_default();
    section(&mut text, "后台状态");
    status(&mut text, now, &devices);

    section(&mut text, "蓝牙");
    for (name, value) in crate::pairing::bluetooth_report() { line(&mut text, name, &value); }

    section(&mut text, &format!("我的设备（{} 块）", devices.len()));
    for device in &devices {
        let _ = writeln!(text, "- {}：{}，{}，靠近 {} dBm，远离 {} dBm，返回窗口 {} 秒，身份{}",
            label(&devices, &device.id), yes_no(device.enabled, "已启用", "已停用"),
            yes_no(device.auto_unlock_on_return, "无感解锁", "需要键鼠确认"),
            device.near_rssi, device.far_rssi, device.return_window_seconds,
            yes_no(registry::identity_configured(&device.id), "已绑定", "未绑定"));
    }

    section(&mut text, "账户与通知");
    line(&mut text, "账户密码", yes_no(crate::enroll::credential_configured(), "已保存", "未保存"));
    line(&mut text, "Windows 动态锁", yes_no(crate::session::dynamic_lock_enabled(), "已开启", "未开启"));
    line(&mut text, "合盖时继续检测手表", yes_no(registry::load_settings().unwrap_or_default().scan_with_lid_closed, "已开启", "未开启"));
    let notifications = registry::load_notifications().unwrap_or_default();
    line(&mut text, "通知", yes_no(notifications.enabled, "已启用", "未启用"));
    line(&mut text, "解锁后通知", yes_no(notifications.notify_on_unlock, "是", "否"));
    line(&mut text, "通知服务器", &url::host(&notifications.endpoint));
    line(&mut text, "Bark 密钥", yes_no(secret_stored("bark-key.dpapi"), "已保存", "未保存"));

    section(&mut text, &format!("最近事件（最多 {EVENTS} 条，按时间顺序）"));
    for event in crate::audit::recent(EVENTS).unwrap_or_default().iter().rev() {
        let device = event.device_id.as_deref().map_or_else(|| "—".into(), |id| label(&devices, id));
        let _ = writeln!(text, "{}  {}  {}  {}", local_time(event.at_ms).unwrap_or_default(), event.event, device, event.detail);
    }

    section(&mut text, &format!("后台守护日志（最后 {SUPERVISOR_LINES} 行）"));
    supervisor_log(&mut text);

    truncate(&mut text, MAX_TEXT);
    Ok(json!({"text": text, "stamp": stamp(now)}))
}

fn section(text: &mut String, title: &str) {
    let _ = write!(text, "\n== {title} ==\n");
}

fn line(text: &mut String, name: &str, value: &str) {
    let _ = writeln!(text, "{name}：{value}");
}

fn yes_no(value: bool, yes: &'static str, no: &'static str) -> &'static str {
    if value { yes } else { no }
}

/// A category only, never the account name.
fn data_owner() -> &'static str {
    use crate::bind::DataOwner;
    let Ok(dir) = registry::data_dir() else { return "未知" };
    if !dir.exists() { return "没有数据目录"; }
    match crate::bind::data_dir_owner(&dir) {
        Ok(DataOwner::CurrentUser) => "当前账户",
        Ok(DataOwner::Administrators) => "管理员组（目录由以管理员身份运行的程序创建）",
        Ok(DataOwner::Other) => "其他账户",
        Err(_) => "未知",
    }
}

fn secret_stored(name: &str) -> bool {
    registry::data_dir().map(|dir| dir.join(name).is_file()).unwrap_or(false)
}

/// "设备 N" by position in the device list, never the name the user gave the watch.
fn label(devices: &[Device], id: &str) -> String {
    devices.iter().position(|device| device.id == id)
        .map_or_else(|| "已删除的设备".into(), |index| format!("设备 {}", index + 1))
}

fn status(text: &mut String, now: u64, devices: &[Device]) {
    let status: Value = registry::data_dir()
        .and_then(|dir| registry::read_json(&dir.join("status.json")))
        .unwrap_or(Value::Null);
    let Some(at) = status.get("at_ms").and_then(Value::as_u64) else {
        line(text, "状态文件", "没有");
        return;
    };
    line(text, "状态更新于", &format!("{} 秒前", now.saturating_sub(at) / 1000));
    for (key, name) in [("running", "后台运行"), ("scanner_active", "蓝牙扫描"), ("provider_ready", "登录组件就绪"),
        ("locked", "屏幕已锁定"), ("submitted_this_lock", "本次锁屏已解锁")] {
        let value = match status.get(key).and_then(Value::as_bool) { Some(true) => "是", Some(false) => "否", None => "—" };
        line(text, name, value);
    }
    for entry in status.get("devices").and_then(Value::as_array).into_iter().flatten() {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or_default();
        let rssi = entry.get("rssi").and_then(Value::as_i64).map_or_else(|| "无信号".into(), |rssi| format!("{rssi} dBm"));
        let presence = match entry.get("presence").and_then(Value::as_str) {
            Some("near") => "在附近", Some("away") => "已离开", _ => "未知",
        };
        line(text, &format!("{} 信号", label(devices, id)), &format!("{rssi}，{presence}"));
    }
}

/// Supervisor lines start with `SystemTime { intervals: <FILETIME> }`; shown as local time.
fn supervisor_log(text: &mut String) {
    let Ok(dir) = registry::data_dir() else { return };
    let lines = read_tail(&dir.join("supervisor.log"));
    if lines.is_empty() { text.push_str("（没有记录）\n"); }
    for raw in lines.iter().rev().take(SUPERVISOR_LINES).rev() {
        let readable = raw.strip_prefix("SystemTime { intervals: ")
            .and_then(|rest| rest.split_once(" } "))
            .and_then(|(ticks, message)| {
                let ticks = ticks.parse::<u64>().ok()?;
                Some(format!("{}  {message}", local_time(ticks.checked_sub(UNIX_EPOCH_TICKS)? / 10_000)?))
            });
        let _ = writeln!(text, "{}", readable.as_deref().unwrap_or(raw));
    }
}

fn read_tail(path: &Path) -> Vec<String> {
    let Ok(bytes) = crate::vault::read_limited_file(path, 1024 * 1024) else { return Vec::new() };
    String::from_utf8_lossy(&bytes).lines().map(|line| line.chars().filter(|c| !c.is_control()).collect()).collect()
}

fn truncate(text: &mut String, limit: usize) {
    if text.len() <= limit { return; }
    let mut end = limit;
    while !text.is_char_boundary(end) { end -= 1; }
    text.truncate(end);
    text.push_str("\n（内容过长，已截断）\n");
}

fn windows_version() -> String {
    let key = w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let name = registry_string(key, w!("ProductName")).unwrap_or_else(|| "Windows".into());
    let release = registry_string(key, w!("DisplayVersion")).unwrap_or_default();
    let build = registry_string(key, w!("CurrentBuild")).unwrap_or_default();
    let update = registry_dword(key, w!("UBR")).map(|value| format!(".{value}")).unwrap_or_default();
    // ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
    let name = if build.parse::<u32>().is_ok_and(|build| build >= 22000) { name.replacen("Windows 10", "Windows 11", 1) } else { name };
    format!("{name} {release}（版本号 {build}{update}）")
}

fn registry_string(key: PCWSTR, value: PCWSTR) -> Option<String> {
    let mut buffer = [0u16; 256];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, None,
        Some(buffer.as_mut_ptr().cast()), Some(&mut size)) };
    if status.is_err() { return None; }
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn registry_dword(key: PCWSTR, value: PCWSTR) -> Option<u32> {
    let mut data = 0u32;
    let mut size = 4u32;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_DWORD, None,
        Some((&mut data as *mut u32).cast()), Some(&mut size)) };
    status.is_ok().then_some(data)
}

fn local_system_time(at_ms: u64) -> Option<SYSTEMTIME> {
    let ticks = at_ms.checked_mul(10_000)?.checked_add(UNIX_EPOCH_TICKS)?;
    let file_time = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    unsafe {
        FileTimeToSystemTime(&file_time, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).ok()?;
    }
    Some(local)
}

fn local_time(at_ms: u64) -> Option<String> {
    let t = local_system_time(at_ms)?;
    Some(format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond))
}

fn stamp(at_ms: u64) -> String {
    local_system_time(at_ms).map_or_else(|| at_ms.to_string(), |t|
        format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond))
}

mod url {
    /// Only the host: a self-hosted endpoint's path or query could carry a token.
    pub fn host(endpoint: &str) -> String {
        let rest = endpoint.split_once("://").map_or(endpoint, |(_, rest)| rest);
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit('@').next().unwrap_or(host);
        if host.is_empty() { "未设置".into() } else { host.chars().filter(|c| !c.is_control()).take(253).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_keeps_only_the_host() {
        assert_eq!(url::host("https://api.day.app/push"), "api.day.app");
        assert_eq!(url::host("https://bark.example.test:8443/push?token=abc"), "bark.example.test:8443");
        assert_eq!(url::host("https://user:pass@bark.example.test/x"), "bark.example.test");
        assert_eq!(url::host(""), "未设置");
    }

    #[test]
    fn devices_are_numbered_instead_of_named() {
        let device = |id: &str| Device { id: id.into(), name: "张三的 Apple Watch".into(), adapter: "apple-ble".into(),
            near_rssi: -60, far_rssi: -80, auto_unlock_on_return: true, enabled: true, address: None,
            return_window_seconds: 30 };
        let devices = [device("a"), device("b")];
        assert_eq!(label(&devices, "b"), "设备 2");
        assert_eq!(label(&devices, "gone"), "已删除的设备");
        assert!(!label(&devices, "a").contains("张三"));
    }

    #[test]
    fn long_reports_are_cut_on_a_character_boundary() {
        let mut text = "解锁".repeat(10);
        truncate(&mut text, 7);
        assert!(text.starts_with("解锁"));
        assert!(text.ends_with("已截断）\n"));
    }

    #[test]
    fn epoch_converts_to_a_local_calendar_time() {
        let shown = local_time(0).expect("conversion");
        assert!(shown.starts_with("1970-01-01") || shown.starts_with("1969-12-31"));
        assert_eq!(stamp(0).len(), 15);
    }
}
