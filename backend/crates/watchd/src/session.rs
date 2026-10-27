//! WTS lock/unlock and power event monitoring.
//!
//! 隐藏消息窗口接收 WM_WTSSESSION_CHANGE / WM_POWERBROADCAST，
//! 经 std mpsc 通道投递到主循环。

use std::sync::mpsc::Sender;
use std::os::windows::process::CommandExt;

use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW};
use windows::Win32::System::Power::{
    RegisterPowerSettingNotification, RegisterSuspendResumeNotification, POWERBROADCAST_SETTING,
};
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSQuerySessionInformationW, WTSRegisterSessionNotification, WTSSessionInfoEx,
    WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK,
    WTS_SESSIONSTATE_UNLOCK,
};
use windows::Win32::System::SystemServices::{
    GUID_LIDSWITCH_STATE_CHANGE, GUID_SESSION_DISPLAY_STATUS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    RegisterClassW, SetWindowLongPtrW, DEVICE_NOTIFY_WINDOW_HANDLE, GWLP_USERDATA, HWND_MESSAGE,
    MSG, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND, PBT_POWERSETTINGCHANGE, WM_POWERBROADCAST,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
};

/// 会话/电源事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Lock,
    Unlock,
    /// 屏幕关闭、合盖或系统挂起。BLE watcher 必须在 Modern Standby 前停止。
    Pause(PauseReason),
    /// 系统刚从挂起状态恢复。只用于恢复内部组件，不直接授权解锁。
    Resume,
    /// 有用户在场含义的唤醒：会话屏幕关闭后点亮，或合盖后开盖。
    Wake(WakeReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    DisplayOff,
    LidClosed,
    SystemSuspend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    DisplayOn,
    LidOpen,
}

/// 电源设置通知会在注册时先报告一次当前状态；只有已经观察到 0 后再收到 1，
/// 才算真实的关闭→打开转换，避免守护启动就误触发解锁。
fn changed_from_off_to_on(previous: Option<u32>, current: u32) -> bool {
    previous == Some(0) && current == 1
}

fn changed_to_off(previous: Option<u32>, current: u32) -> bool {
    current == 0 && previous != Some(0)
}

struct EventContext {
    sender: Sender<SessionEvent>,
    display_state: Option<u32>,
    lid_state: Option<u32>,
}

fn locked_from_session_flags(flags: i32) -> anyhow::Result<bool> {
    match flags as u32 {
        WTS_SESSIONSTATE_LOCK => Ok(true),
        WTS_SESSIONSTATE_UNLOCK => Ok(false),
        other => anyhow::bail!("未知 WTS SessionFlags: {other}"),
    }
}

/// Windows「动态锁」（设置 → 账户 → 登录选项）是否开启。只用于推测锁屏原因和诊断。
pub fn dynamic_lock_enabled() -> bool {
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let mut data = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, w!("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
            w!("EnableGoodbye"), RRF_RT_REG_DWORD, None, Some((&mut data as *mut u32).cast()), Some(&mut size))
    };
    status.is_ok() && data != 0
}

/// 主动查询当前 WTS 会话的锁定状态。
///
/// 部分 Modern Standby/开合盖顺序会漏掉 `WM_WTSSESSION_CHANGE/LOCK`，所以唤醒和
/// Provider 握手时用此查询校准缓存状态，不能只依赖事件通知。
pub fn current_session_locked() -> anyhow::Result<bool> {
    unsafe {
        let mut buffer = windows::core::PWSTR::null();
        let mut bytes = 0u32;
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )?;

        let result = (|| -> anyhow::Result<bool> {
            anyhow::ensure!(!buffer.is_null(), "WTSSessionInfoEx 返回空缓冲区");
            anyhow::ensure!(
                bytes as usize >= std::mem::size_of::<WTSINFOEXW>(),
                "WTSSessionInfoEx 缓冲区过短: {bytes}"
            );
            let info = &*(buffer.0 as *const WTSINFOEXW);
            anyhow::ensure!(
                info.Level == 1,
                "不支持的 WTSSessionInfoEx Level: {}",
                info.Level
            );
            locked_from_session_flags(info.Data.WTSInfoExLevel1.SessionFlags)
        })();

        if !buffer.is_null() {
            WTSFreeMemory(buffer.0 as *mut core::ffi::c_void);
        }
        result
    }
}

/// 微软账户身份缓存（注册表读取较慢，启动后只查一次）。
static MSA_IDENTITY: std::sync::OnceLock<Option<(String, String)>> = std::sync::OnceLock::new();

/// 从 IdentityStore\LogonCache 注册表查找本机微软账户身份（邮箱 + 授权域），结果缓存。
pub fn msa_identity() -> Option<(String, String)> {
    MSA_IDENTITY.get_or_init(msa_identity_lookup).clone()
}

/// 当前会话可用于 LogonUser/Winlogon 的身份候选。
/// 登记时逐个用用户输入的账户密码校验，最终只保存实际通过验证的身份。
pub fn identity_candidates() -> Vec<(String, String)> {
    let mut result = Vec::new();
    if let Some(msa) = msa_identity() {
        result.push(msa);
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let domain = std::env::var("USERDOMAIN")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| ".".into());
        if !username.is_empty()
            && !result
                .iter()
                .any(|(u, d)| u.eq_ignore_ascii_case(&username) && d.eq_ignore_ascii_case(&domain))
        {
            result.push((username, domain));
        }
    }
    result
}

const LOGON_CACHE: &str = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IdentityStore\\LogonCache";

fn current_user_sid() -> Option<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let result = (|| {
            let mut required = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut required);
            if required == 0 { return None; }
            let mut buffer = vec![0usize; (required as usize + std::mem::size_of::<usize>() - 1)
                / std::mem::size_of::<usize>()];
            GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), required, &mut required).ok()?;
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut text = windows::core::PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut text).ok()?;
            let value = text.to_string().ok();
            let _ = LocalFree(HLOCAL(text.0.cast()));
            value
        })();
        let _ = CloseHandle(token);
        result
    }
}

fn system_reg() -> Option<std::path::PathBuf> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() { return None; }
    Some(std::path::PathBuf::from(String::from_utf16(&buffer[..length]).ok()?).join("reg.exe"))
}

fn query_registry(reg: &std::path::Path, key: &str) -> Option<String> {
    let output = std::process::Command::new(reg).args(["query", key])
        .creation_flags(CREATE_NO_WINDOW.0).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn cache_nodes(output: &str) -> Vec<String> {
    let prefix = format!("{LOGON_CACHE}\\");
    output.lines().map(str::trim).filter(|line| {
        line.get(..prefix.len()).is_some_and(|start| start.eq_ignore_ascii_case(&prefix))
            && line.get(prefix.len()..).is_some_and(|key| !key.is_empty() && !key.contains('\\'))
    }).map(str::to_owned).collect()
}

fn current_sid_node(output: &str, parent: &str, current_sid: &str) -> Option<String> {
    let expected = format!("{parent}\\{current_sid}");
    output.lines().any(|line| line.trim().eq_ignore_ascii_case(&expected)).then_some(expected)
}

fn identity_fields(output: &str) -> Option<(String, String)> {
    let field = |name: &str| output.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next()?.eq_ignore_ascii_case(name) && parts.next()? == "REG_SZ")
            .then(|| parts.next().map(str::to_owned)).flatten()
    });
    let name = field("IdentityName")?;
    let authority = field("AuthenticatingAuthority")?;
    name.contains('@').then_some((name, authority))
}

fn msa_identity_lookup() -> Option<(String, String)> {
    let sid = current_user_sid()?;
    let reg = system_reg()?;
    let listing = query_registry(&reg, LOGON_CACHE)?;
    cache_nodes(&listing).into_iter().find_map(|cache| {
        let parent = format!("{cache}\\Sid2Name");
        let nodes = query_registry(&reg, &parent)?;
        let node = current_sid_node(&nodes, &parent, &sid)?;
        // Other users' nodes are never queried for account identities.
        identity_fields(&query_registry(&reg, &node)?)
    })
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let context = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut EventContext;
    if !context.is_null() {
        let context = &mut *context;
        if msg == WM_WTSSESSION_CHANGE {
            match wparam.0 as u32 {
                WTS_SESSION_LOCK => {
                    let _ = context.sender.send(SessionEvent::Lock);
                }
                WTS_SESSION_UNLOCK => {
                    let _ = context.sender.send(SessionEvent::Unlock);
                }
                _ => {}
            }
        } else if msg == WM_POWERBROADCAST {
            match wparam.0 as u32 {
                PBT_APMSUSPEND => {
                    let _ = context
                        .sender
                        .send(SessionEvent::Pause(PauseReason::SystemSuspend));
                }
                PBT_APMRESUMEAUTOMATIC => {
                    let _ = context.sender.send(SessionEvent::Resume);
                }
                PBT_POWERSETTINGCHANGE if lparam.0 != 0 => {
                    let setting = &*(lparam.0 as *const POWERBROADCAST_SETTING);
                    if setting.DataLength >= std::mem::size_of::<u32>() as u32 {
                        let value = std::ptr::read_unaligned(setting.Data.as_ptr() as *const u32);
                        if setting.PowerSetting == GUID_SESSION_DISPLAY_STATUS {
                            let previous = context.display_state.replace(value);
                            tracing::info!(
                                "[POWER] 会话屏幕状态: {previous:?} -> {value}（0=关闭 1=点亮 2=变暗）"
                            );
                            if changed_to_off(previous, value) {
                                let _ = context
                                    .sender
                                    .send(SessionEvent::Pause(PauseReason::DisplayOff));
                            } else if changed_from_off_to_on(previous, value) {
                                let _ = context
                                    .sender
                                    .send(SessionEvent::Wake(WakeReason::DisplayOn));
                            }
                        } else if setting.PowerSetting == GUID_LIDSWITCH_STATE_CHANGE {
                            let previous = context.lid_state.replace(value);
                            tracing::info!(
                                "[POWER] 机盖状态: {previous:?} -> {value}（0=关闭 1=打开）"
                            );
                            if changed_to_off(previous, value) {
                                let _ = context
                                    .sender
                                    .send(SessionEvent::Pause(PauseReason::LidClosed));
                            } else if changed_from_off_to_on(previous, value) {
                                let _ =
                                    context.sender.send(SessionEvent::Wake(WakeReason::LidOpen));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// 启动会话事件线程：创建隐藏窗口、注册 WTS/电源通知、跑消息循环。
pub fn start_session_events(tx: Sender<SessionEvent>) -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("session-events".into())
        .spawn(move || unsafe {
            if let Err(e) = event_loop(tx) {
                tracing::error!("会话事件循环退出: {e}");
            }
        })?;
    Ok(())
}

unsafe fn event_loop(tx: Sender<SessionEvent>) -> windows::core::Result<()> {
    let instance = GetModuleHandleW(None)?.into();
    let class_name = w!("WatchUnlockSessionWnd");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: instance,
        lpszClassName: class_name,
        ..Default::default()
    };
    let _ = RegisterClassW(&wc); // 重复注册（ERROR_CLASS_ALREADY_EXISTS）可容忍

    let context_box = Box::into_raw(Box::new(EventContext {
        sender: tx,
        display_state: None,
        lid_state: None,
    }));
    let hwnd = CreateWindowExW(
        Default::default(),
        class_name,
        w!(""),
        Default::default(),
        0,
        0,
        0,
        0,
        HWND_MESSAGE,
        None,
        instance,
        Some(context_box as *const core::ffi::c_void),
    )?;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, context_box as isize);

    // NOTIFY_FOR_THIS_SESSION = 0。注册失败时主动查询仍可兜底，但必须留下诊断日志。
    match WTSRegisterSessionNotification(hwnd, 0) {
        Ok(()) => tracing::info!("WTS 会话锁定通知注册成功"),
        Err(error) => tracing::warn!("WTS 会话锁定通知注册失败，将依赖主动状态校准: {error}"),
    }
    let _hpower = RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE);
    let _display_power = match RegisterPowerSettingNotification(
        hwnd,
        &GUID_SESSION_DISPLAY_STATUS,
        DEVICE_NOTIFY_WINDOW_HANDLE,
    ) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!("注册会话屏幕状态通知失败: {e}");
            None
        }
    };
    let _lid_power = match RegisterPowerSettingNotification(
        hwnd,
        &GUID_LIDSWITCH_STATE_CHANGE,
        DEVICE_NOTIFY_WINDOW_HANDLE,
    ) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!("注册开合盖状态通知失败: {e}");
            None
        }
    };
    tracing::info!("会话事件监听已启动（锁屏/解锁/睡眠恢复/屏幕点亮/开盖）");

    let mut msg = MSG::default();
    loop {
        let ret = GetMessageW(&mut msg, HWND::default(), 0, 0);
        if ret.0 <= 0 {
            break; // WM_QUIT 或错误
        }
        let _ = DispatchMessageW(&msg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cache_nodes, changed_from_off_to_on, changed_to_off, current_sid_node,
        identity_fields, locked_from_session_flags, LOGON_CACHE};
    use windows::Win32::System::RemoteDesktop::{WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK};

    #[test]
    fn initial_on_state_is_not_a_wake() {
        assert!(!changed_from_off_to_on(None, 1));
    }

    #[test]
    fn only_off_to_on_is_a_wake() {
        assert!(changed_from_off_to_on(Some(0), 1));
        assert!(!changed_from_off_to_on(Some(1), 1));
        assert!(!changed_from_off_to_on(Some(2), 1));
        assert!(!changed_from_off_to_on(Some(0), 2));
    }

    #[test]
    fn initial_or_real_off_state_pauses_scanning_once() {
        assert!(changed_to_off(None, 0));
        assert!(changed_to_off(Some(1), 0));
        assert!(changed_to_off(Some(2), 0));
        assert!(!changed_to_off(Some(0), 0));
        assert!(!changed_to_off(Some(0), 1));
    }

    #[test]
    fn wts_session_flags_map_to_lock_state() {
        assert!(locked_from_session_flags(WTS_SESSIONSTATE_LOCK as i32).unwrap());
        assert!(!locked_from_session_flags(WTS_SESSIONSTATE_UNLOCK as i32).unwrap());
        assert!(locked_from_session_flags(99).is_err());
    }

    #[test]
    fn identity_lookup_only_lists_direct_cache_children() {
        let listing = format!("{LOGON_CACHE}\n{LOGON_CACHE}\\{{cache-one}}\n\
            {LOGON_CACHE}\\{{cache-one}}\\Sid2Name\nHKEY_LOCAL_MACHINE\\unrelated\n");
        assert_eq!(cache_nodes(&listing), vec![format!("{LOGON_CACHE}\\{{cache-one}}")]);
    }

    #[test]
    fn another_users_first_cached_sid_is_never_selected() {
        let parent = format!("{LOGON_CACHE}\\{{cache-one}}\\Sid2Name");
        let current = "S-1-5-21-100-200-300-1001";
        let other = "S-1-5-21-100-200-300-1002";
        let listing = format!("{parent}\n{parent}\\{other}\n{parent}\\{current}\n");
        assert_eq!(current_sid_node(&listing, &parent, current), Some(format!("{parent}\\{current}")));
        assert!(current_sid_node(&format!("{parent}\\{other}"), &parent, current).is_none());
        assert!(current_sid_node(&format!("{parent}\\{current}-extra"), &parent, current).is_none());
    }

    #[test]
    fn selected_identity_values_require_an_email_and_explicit_string_fields() {
        let selected = "IdentityName REG_SZ current@example.test\nAuthenticatingAuthority REG_SZ MicrosoftAccount\n";
        assert_eq!(identity_fields(selected), Some(("current@example.test".into(), "MicrosoftAccount".into())));
        assert!(identity_fields("IdentityName REG_SZ local\nAuthenticatingAuthority REG_SZ MicrosoftAccount").is_none());
        assert!(identity_fields("IdentityName REG_BINARY 01\nAuthenticatingAuthority REG_SZ MicrosoftAccount").is_none());
        assert!(identity_fields("IdentityName REG_SZ current@example.test").is_none());
    }
}
