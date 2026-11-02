//! 与守护的命名管道通信（provider 侧客户端）。
//! Trust is anchored in the protected Program Files folder this DLL was registered from, and in
//! the locked session's user SID.
//!
//! Normally the logon screen and the daemon share a session. After a closed Remote Desktop
//! connection (or `tsdiscon`, switch user) the user's session is disconnected and the physical
//! screen shows an empty logon session instead; only that screen then talks to the daemons of
//! the disconnected sessions, and relays its keyboard and mouse input, which they cannot see.

use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeServerSessionId, GetNamedPipeServerProcessId, PeekNamedPipe, SetNamedPipeHandleState,
    PIPE_NOWAIT, PIPE_READMODE_BYTE,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_WARNING_TYPE,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSDisconnected, WTSDomainName, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SERVER_HANDLE,
    WTS_INFO_CLASS, WTS_SESSION_INFOW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, LookupAccountNameW, TokenUser, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT};

const MAX_FRAME_BYTES: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
pub struct PipeMsg {
    pub msg: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub echo: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    /// GetTickCount value of this logon screen's last keyboard or mouse input; sent only to the
    /// daemon of a disconnected session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u32>,
}

impl Drop for PipeMsg {
    fn drop(&mut self) {
        if let Some(password) = self.password.as_mut() {
            crate::clear_secret(password);
        }
    }
}

/// 解锁信号（nonce 已回显验证；nonce 本身不是身份认证）。
pub struct UnlockSignal {
    pub password: String,
    pub username: String,
    pub domain: String,
}

impl Drop for UnlockSignal {
    fn drop(&mut self) {
        crate::clear_secret(&mut self.password);
    }
}

fn clear_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A connection carries exactly one newline-terminated JSON message per direction.
/// Accumulate bytes before decoding UTF-8, which may be split across ReadFile calls.
struct FrameReader {
    bytes: Vec<u8>,
    complete: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
        // Avoid reallocating a partially received password into an abandoned allocation.
        Self { bytes: Vec::with_capacity(MAX_FRAME_BYTES), complete: false }
    }
}

impl FrameReader {
    fn push(&mut self, chunk: &[u8]) -> Result<Option<PipeMsg>, ()> {
        if self.complete || self.bytes.len() + chunk.len() > MAX_FRAME_BYTES {
            return Err(());
        }
        self.bytes.extend_from_slice(chunk);
        let Some(end) = self.bytes.iter().position(|&byte| byte == b'\n') else {
            return Ok(None);
        };
        // Reject coalesced duplicates instead of delivering multiple credentials.
        if end + 1 != self.bytes.len() {
            return Err(());
        }
        self.complete = true;
        let result = serde_json::from_slice(&self.bytes[..end]).map_err(|_| ());
        clear_bytes(&mut self.bytes);
        self.bytes.clear();
        result.map(Some)
    }
}

impl Drop for FrameReader {
    fn drop(&mut self) {
        clear_bytes(&mut self.bytes);
    }
}

/// 指定会话的管道全名（守护按自己的 SessionId 命名）。
fn pipe_name(session: u32) -> String {
    #[cfg(test)]
    if let Ok(name) = std::env::var("WATCH_UNLOCK_PIPE") {
        return format!("\\\\.\\pipe\\{name}");
    }
    format!("\\\\.\\pipe\\WatchUnlockWindows-{session}")
}

fn own_session() -> u32 {
    let mut session = 0u32;
    unsafe { let _ = ProcessIdToSessionId(std::process::id(), &mut session); }
    session
}

/// Sessions whose daemon this logon screen talks to. A logon screen inside a user's session
/// serves that session only. The empty logon session on the physical screen serves the
/// disconnected user sessions, which signing in there reconnects. Any other logon screen,
/// such as a Remote Desktop one, never qualifies for them.
fn pick_targets(own: u32, own_has_user: bool, console: Option<u32>, sessions: &[(u32, bool, bool)]) -> Vec<u32> {
    if own_has_user || console != Some(own) { return vec![own]; }
    let disconnected: Vec<u32> = sessions.iter()
        .filter(|&&(id, disconnected, has_user)| id != own && disconnected && has_user)
        .map(|&(id, ..)| id).collect();
    if disconnected.is_empty() { vec![own] } else { disconnected }
}

fn targets() -> Vec<u32> {
    let own = own_session();
    #[cfg(test)]
    if std::env::var("WATCH_UNLOCK_PIPE").is_ok() { return vec![own]; }
    let own_has_user = wts_text(own, WTSUserName).is_some();
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let console = (console != u32::MAX).then_some(console);
    let mut sessions = Vec::new();
    if !own_has_user && console == Some(own) {
        unsafe {
            let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
            let mut count = 0u32;
            if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count).is_ok() && !info.is_null() {
                for entry in std::slice::from_raw_parts(info, count as usize) {
                    sessions.push((entry.SessionId, entry.State == WTSDisconnected,
                        wts_text(entry.SessionId, WTSUserName).is_some()));
                }
                WTSFreeMemory(info.cast());
            }
        }
    }
    pick_targets(own, own_has_user, console, &sessions)
}

/// GetTickCount value of this session's last keyboard or mouse input.
fn last_input_tick() -> Option<u32> {
    let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    unsafe { GetLastInputInfo(&mut info) }.as_bool().then_some(info.dwTime)
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } }
}

struct TrustedConnection { pipe: OwnedHandle, _process: OwnedHandle }

fn token_user(token: HANDLE) -> Option<Vec<usize>> {
    unsafe {
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        if size == 0 { return None; }
        let mut buffer = vec![0usize; (size as usize + 7) / std::mem::size_of::<usize>()];
        GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), size, &mut size).ok()?;
        Some(buffer)
    }
}

/// The logon UI cannot write files, so a rejected server is reported to the Application event
/// log (source "WatchUnlockWindows"), at most once a minute per stage. Stage names only.
fn report(stage: &'static str) {
    static LAST: std::sync::Mutex<Vec<(&'static str, std::time::Instant)>> = std::sync::Mutex::new(Vec::new());
    let Ok(mut last) = LAST.lock() else { return };
    let now = std::time::Instant::now();
    if let Some((_, at)) = last.iter_mut().find(|(name, _)| *name == stage) {
        if now.duration_since(*at) < Duration::from_secs(60) { return; }
        *at = now;
    } else {
        last.push((stage, now));
    }
    drop(last);
    let source: Vec<u16> = "WatchUnlockWindows\0".encode_utf16().collect();
    let text: Vec<u16> = format!("Watch Unlock provider rejected the background: {stage}\0").encode_utf16().collect();
    unsafe {
        let Ok(log) = RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) else { return };
        let strings = [PCWSTR(text.as_ptr())];
        let _ = ReportEventW(log, EVENTLOG_WARNING_TYPE, 0, 1000, None, 0, Some(&strings), None);
        let _ = DeregisterEventSource(log);
    }
}

/// Records in the Application event log that Windows refused a credential this provider
/// submitted. Only the NTSTATUS code; never the account or password.
pub(crate) fn report_rejected_logon(status: i32) {
    let source: Vec<u16> = "WatchUnlockWindows\0".encode_utf16().collect();
    let text: Vec<u16> = format!("Watch Unlock provider: Windows rejected the submitted logon, NTSTATUS 0x{status:08X}\0")
        .encode_utf16().collect();
    unsafe {
        let Ok(log) = RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) else { return };
        let strings = [PCWSTR(text.as_ptr())];
        let _ = ReportEventW(log, EVENTLOG_WARNING_TYPE, 0, 1001, None, 0, Some(&strings), None);
        let _ = DeregisterEventSource(log);
    }
}

fn wts_text(session: u32, class: WTS_INFO_CLASS) -> Option<String> {
    unsafe {
        let mut buffer = PWSTR::null();
        let mut bytes = 0u32;
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, class, &mut buffer, &mut bytes).ok()?;
        let value = buffer.to_string().ok();
        WTSFreeMemory(buffer.0.cast());
        value.filter(|text| !text.is_empty())
    }
}

/// SID of the user signed in to `session`. Unlike WTSQueryUserToken this needs no
/// SeTcbPrivilege, which the logon UI process does not hold.
fn session_user_sid(session: u32) -> Option<Vec<u8>> {
    let user = wts_text(session, WTSUserName)?;
    let domain = wts_text(session, WTSDomainName).unwrap_or_default();
    let account: Vec<u16> = format!("{domain}\\{user}").encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut kind = SID_NAME_USE::default();
        let _ = LookupAccountNameW(PCWSTR::null(), PCWSTR(account.as_ptr()), PSID::default(),
            &mut sid_size, PWSTR::null(), &mut domain_size, &mut kind);
        if sid_size == 0 { return None; }
        let mut sid = vec![0u8; sid_size as usize];
        let mut referenced = vec![0u16; domain_size.max(1) as usize];
        LookupAccountNameW(PCWSTR::null(), PCWSTR(account.as_ptr()), PSID(sid.as_mut_ptr().cast()),
            &mut sid_size, PWSTR(referenced.as_mut_ptr()), &mut domain_size, &mut kind).ok()?;
        Some(sid)
    }
}

/// Folder holding this DLL. LogonUI loads it from the path registered under HKLM, which only
/// administrators can change.
fn module_directory() -> Result<String, &'static str> {
    unsafe {
        let mut module = HMODULE::default();
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(module_directory as *const () as *const u16), &mut module).map_err(|_| "module_path")?;
        let mut path = [0u16; 32768];
        let length = GetModuleFileNameW(module, &mut path) as usize;
        if length == 0 || length >= path.len() { return Err("module_path"); }
        let path = String::from_utf16(&path[..length]).map_err(|_| "module_path")?;
        Ok(path.rsplit_once('\\').ok_or("module_path")?.0.to_owned())
    }
}

/// The only daemon trusted is `watchd.exe` beside this DLL, and only when that folder lies inside
/// Program Files, whose default ACL lets only administrators write.
fn trusted_daemon_path(module_dir: &str, program_files: &str) -> Option<String> {
    let prefix = module_dir.get(..program_files.len())?;
    let inside = prefix.eq_ignore_ascii_case(program_files)
        && module_dir[program_files.len()..].starts_with('\\')
        && module_dir.len() > program_files.len() + 1
        && !module_dir.contains("..");
    inside.then(|| format!("{module_dir}\\watchd.exe"))
}

fn trusted_server(pipe: HANDLE) -> Option<OwnedHandle> {
    match check_server(pipe) {
        Ok(process) => Some(process),
        Err(stage) => { report(stage); None }
    }
}

fn check_server(pipe: HANDLE) -> Result<OwnedHandle, &'static str> {
    unsafe {
        let mut pid = 0;
        GetNamedPipeServerProcessId(pipe, &mut pid).map_err(|_| "server_pid")?;
        let process = OwnedHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|_| "open_process")?);
        let mut path = [0u16; 32768];
        let mut length = path.len() as u32;
        QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut length)
            .map_err(|_| "image_path")?;
        let actual = String::from_utf16(&path[..length as usize]).map_err(|_| "image_path")?;
        let program_files = SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None)
            .map_err(|_| "program_files")?;
        let root = program_files.to_string();
        CoTaskMemFree(Some(program_files.0.cast()));
        let expected = trusted_daemon_path(&module_directory()?, &root.map_err(|_| "program_files")?)
            .ok_or("outside_program_files")?;
        if !actual.eq_ignore_ascii_case(&expected) { return Err("unexpected_path"); }
        let mut session = 0;
        ProcessIdToSessionId(pid, &mut session).map_err(|_| "server_session")?;
        let mut user_sid = session_user_sid(session).ok_or("session_user")?;
        let mut server_token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &mut server_token).map_err(|_| "server_token")?;
        let server_token = OwnedHandle(server_token);
        let server_buffer = token_user(server_token.0).ok_or("server_token")?;
        let server = &*server_buffer.as_ptr().cast::<TOKEN_USER>();
        EqualSid(PSID(user_sid.as_mut_ptr().cast()), server.User.Sid).map_err(|_| "user_mismatch")?;
        Ok(process)
    }
}

/// Read-only trust inspection, also used by isolated negative integration tests.
pub fn is_trusted_server(pipe: HANDLE) -> bool { trusted_server(pipe).is_some() }

/// Opens `name` only when its server runs in `target`, the session chosen by [`targets`].
fn connect(name: &str, target: u32, verifier: fn(HANDLE) -> Option<OwnedHandle>) -> Option<TrustedConnection> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let handle = CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            // LogonUI runs as SYSTEM: never let a pipe server impersonate it.
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        ).ok()?;
        let mut server_session = 0;
        let expected_session = GetNamedPipeServerSessionId(handle, &mut server_session).is_ok()
            && server_session == target;
        // A hostile server must not keep the DLL worker in a blocking write.
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        let pipe = OwnedHandle(handle);
        if !expected_session { report("pipe_session"); return None; }
        let process = verifier(handle)?;
        SetNamedPipeHandleState(handle, Some(&mode), None, None).ok()?;
        Some(TrustedConnection { pipe, _process: process })
    }
}

/// How a connection to a daemon in another session behaves.
#[derive(Clone, Copy)]
struct Remote {
    /// Relay this screen's keyboard and mouse input, which that session cannot see.
    relay_input: bool,
    /// Give up after this long so the other disconnected sessions get their turn.
    hold: Option<Duration>,
}

const LOCAL: Remote = Remote { relay_input: false, hold: None };
/// Input frames at most this often: one is enough to prove the input, the rest keep it fresh.
const INPUT_INTERVAL: Duration = Duration::from_millis(250);

fn write_frame(handle: HANDLE, message: &PipeMsg) -> Option<()> {
    let mut out = serde_json::to_vec(message).ok()?;
    out.push(b'\n');
    let mut written = 0;
    let ok = unsafe { WriteFile(handle, Some(&out), Some(&mut written), None) }.is_ok()
        && written as usize == out.len();
    ok.then_some(())
}

fn input_frame(tick: u32) -> PipeMsg {
    PipeMsg { msg: "input".into(), nonce: None, echo: None, password: None, username: None,
        domain: None, input: Some(tick) }
}

fn receive_message(handle: HANDLE, stop: &AtomicBool, remote: Remote, mut sent_input: Option<u32>) -> Option<PipeMsg> {
    let mut frame = FrameReader::default();
    let started = std::time::Instant::now();
    let mut last_send = started;
    loop {
        if stop.load(Ordering::Acquire) { return None; }
        if remote.hold.is_some_and(|hold| started.elapsed() >= hold) { return None; }
        if remote.relay_input && last_send.elapsed() >= INPUT_INTERVAL {
            if let Some(tick) = last_input_tick().filter(|tick| Some(*tick) != sent_input) {
                write_frame(handle, &input_frame(tick))?;
                sent_input = Some(tick);
                last_send = std::time::Instant::now();
            }
        }
        let mut available = 0;
        if unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }.is_err() {
            return None;
        }
        if available == 0 {
            // 锁定会话中常驻轮询；20ms 兼顾解锁延迟与空转开销。
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        let mut buffer = [0u8; 1024];
        let mut read = 0;
        let status = unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut read), None) };
        let message = if status.is_ok() && read > 0 {
            frame.push(&buffer[..read as usize])
        } else {
            Err(())
        };
        clear_bytes(&mut buffer);
        match message {
            Ok(Some(message)) => return Some(message),
            Ok(None) => {},
            Err(()) => return None,
        }
    }
}

fn exchange(handle: HANDLE, stop: &AtomicBool, remote: Remote) -> Option<UnlockSignal> {
    let mut random = [0u8; 32];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok().ok()?; }
    let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let input = if remote.relay_input { last_input_tick() } else { None };
    let hello = PipeMsg {
        msg: "hello".into(), nonce: Some(nonce.clone()), echo: None,
        password: None, username: None, domain: None, input,
    };
    write_frame(handle, &hello)?;
    // Poll before reading so UnAdvise can cancel while the daemon is silent.
    let message = receive_message(handle, stop, remote, input)?;
    validate_message(message, &nonce)
}

fn validate_message(mut message: PipeMsg, nonce: &str) -> Option<UnlockSignal> {
    if message.msg != "unlock" || message.echo.as_deref() != Some(nonce) {
        return None;
    }
    Some(UnlockSignal {
        password: message.password.take()?,
        username: message.username.take()?,
        domain: message.domain.take()?,
    })
}

/// 断开时重连；本 provider 实例成功接收一次凭据后终止线程。
pub fn run_pipe_client(
    stop: Arc<AtomicBool>,
    on_unlock: impl Fn(UnlockSignal) + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    run_pipe_client_internal(stop, on_unlock, trusted_server)
}

fn run_pipe_client_internal(
    stop: Arc<AtomicBool>,
    on_unlock: impl Fn(UnlockSignal) + Send + 'static,
    verifier: fn(HANDLE) -> Option<OwnedHandle>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("provider-pipe".into())
        .spawn(move || {
            let Ok(_apartment) = crate::events::Apartment::new() else { return; };
            let own = own_session();
            while !stop.load(Ordering::Acquire) {
                // Re-evaluated each round: sessions disconnect and reconnect while this screen waits.
                let targets = targets();
                let several = targets.len() > 1;
                for target in targets {
                    if stop.load(Ordering::Acquire) { return; }
                    let remote = if target == own { LOCAL } else {
                        Remote { relay_input: true, hold: several.then_some(Duration::from_secs(3)) }
                    };
                    if let Some(connection) = connect(&pipe_name(target), target, verifier) {
                        let signal = exchange(connection.pipe.0, &stop, remote);
                        drop(connection);
                        if let Some(signal) = signal {
                            if stop.load(Ordering::Acquire) { return; }
                            tracing::info!("[PROVIDER-PIPE] 收到解锁信号（echo 验证通过）");
                            on_unlock(signal);
                            return;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_must_sit_beside_this_dll_inside_program_files() {
        let root = r"C:\Program Files";
        assert_eq!(trusted_daemon_path(r"C:\Program Files\Watch Unlock", root).as_deref(),
            Some(r"C:\Program Files\Watch Unlock\watchd.exe"));
        assert_eq!(trusted_daemon_path(r"c:\program files\Custom", root).as_deref(),
            Some(r"c:\program files\Custom\watchd.exe"));
        for outside in [r"C:\Program Files", r"C:\Program Files (x86)\Watch Unlock", r"C:\Program FilesX\A",
            r"D:\Apps\Watch Unlock", r"C:\Program Files\..\Users\a", r"C:\Prog", ""] {
            assert!(trusted_daemon_path(outside, root).is_none(), "{outside} must not be trusted");
        }
    }

    #[test]
    fn only_the_empty_console_logon_screen_serves_disconnected_sessions() {
        // (session, disconnected, user signed in)
        let sessions = [(0, true, false), (1, true, true), (2, false, false), (4, true, true), (5, false, true)];
        // A lock screen inside a user's session serves that session only.
        assert_eq!(pick_targets(1, true, Some(1), &sessions), vec![1]);
        // The empty logon session on the physical screen serves the disconnected user sessions.
        assert_eq!(pick_targets(2, false, Some(2), &sessions), vec![1, 4]);
        // A Remote Desktop logon screen is not on the physical screen.
        assert_eq!(pick_targets(3, false, Some(2), &sessions), vec![3]);
        assert_eq!(pick_targets(2, false, None, &sessions), vec![2]);
        // First sign-in after boot: nothing disconnected, so its own (absent) daemon as before.
        assert_eq!(pick_targets(1, false, Some(1), &[(0, true, false), (1, false, false)]), vec![1]);
    }

    #[test]
    fn hello_and_input_frames_never_carry_secrets() {
        let wire = serde_json::to_string(&input_frame(7)).unwrap();
        assert!(wire.contains("\"msg\":\"input\"") && wire.contains("\"input\":7"));
        let hello = PipeMsg { msg: "hello".into(), nonce: Some("00".into()), echo: None, password: None,
            username: None, domain: None, input: None };
        assert!(!serde_json::to_string(&hello).unwrap().contains("input"));
    }

    #[test]
    fn fragmented_utf8_waits_for_newline() {
        let wire = "{\"msg\":\"unlock\",\"password\":\"中文\"}\n";
        let mut frame = FrameReader::default();
        for (index, byte) in wire.bytes().enumerate() {
            let result = frame.push(&[byte]).unwrap();
            if index + 1 == wire.len() {
                assert_eq!(result.unwrap().password.as_deref(), Some("中文"));
            } else {
                assert!(result.is_none());
            }
        }
        assert!(frame.push(b"{}\n").is_err());
    }

    #[test]
    fn rejects_oversized_malformed_and_multiple_frames() {
        assert!(FrameReader::default().push(&vec![b'a'; MAX_FRAME_BYTES + 1]).is_err());
        assert!(FrameReader::default().push(b"not-json\n").is_err());
        assert!(FrameReader::default().push(b"{\"msg\":\"unlock\"}\n{\"msg\":\"unlock\"}\n").is_err());
    }

    #[test]
    fn credential_response_requires_nonce_and_all_fields() {
        let wire = br#"{"msg":"unlock","echo":"0123","password":"dummy","username":"test","domain":"test"}"#;
        let good = validate_message(serde_json::from_slice(wire).unwrap(), "0123");
        assert!(good.is_some());
        assert!(validate_message(serde_json::from_slice(wire).unwrap(), "wrong").is_none());
        let absent = br#"{"msg":"unlock","echo":"0123","username":"test","domain":"test"}"#;
        assert!(validate_message(serde_json::from_slice(absent).unwrap(), "0123").is_none());
    }

    #[test]
    fn silent_server_does_not_prevent_worker_cancellation() {
        use windows::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING};
        use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX, FILE_FLAG_FIRST_PIPE_INSTANCE};
        use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_REJECT_REMOTE_CLIENTS};
        use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        use windows::Win32::Security::{GetTokenInformation, RevertToSelf,
            SecurityIdentification, TokenImpersonationLevel, SECURITY_IMPERSONATION_LEVEL, TOKEN_QUERY};
        let leaf = format!("WatchUnlock-Cancel-Test-{}", std::process::id());
        std::env::set_var("WATCH_UNLOCK_PIPE", &leaf);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (hello_tx, hello_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || unsafe {
            let wide: Vec<u16> = format!("\\\\.\\pipe\\{leaf}").encode_utf16().chain(Some(0)).collect();
            let handle = CreateNamedPipeW(PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, 4096, 4096, 0, None);
            assert!(!handle.is_invalid());
            ready_tx.send(()).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match ConnectNamedPipe(handle, None) {
                    Ok(()) => break,
                    Err(error) if error.code().0 as u32 & 0xffff == ERROR_PIPE_CONNECTED.0 => break,
                    Err(error) => assert_eq!(error.code().0 as u32 & 0xffff, ERROR_PIPE_LISTENING.0),
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            loop {
                let mut buffer = [0u8; 1024];
                let mut read = 0;
                match ReadFile(handle, Some(&mut buffer), Some(&mut read), None) {
                    Ok(()) if read > 0 => break,
                    Ok(()) => {},
                    Err(error) => assert_eq!(error.code().0 as u32 & 0xffff, ERROR_NO_DATA.0),
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            // The client may identify itself, but must not grant impersonation rights.
            ImpersonateNamedPipeClient(handle).unwrap();
            let mut token = HANDLE::default();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
            RevertToSelf().unwrap();
            opened.unwrap();
            let mut level = SECURITY_IMPERSONATION_LEVEL::default();
            let mut returned = 0;
            GetTokenInformation(token, TokenImpersonationLevel,
                Some((&mut level as *mut SECURITY_IMPERSONATION_LEVEL).cast()),
                std::mem::size_of_val(&level) as u32, &mut returned).unwrap();
            CloseHandle(token).unwrap();
            assert_eq!(level, SecurityIdentification);
            hello_tx.send(()).unwrap();
            let _ = done_rx.recv_timeout(Duration::from_secs(5));
            CloseHandle(handle).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        fn test_verifier(_: HANDLE) -> Option<OwnedHandle> {
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::process::id()).ok().map(OwnedHandle) }
        }
        let worker = run_pipe_client_internal(stop.clone(), |_| panic!("silent server returned a credential"), test_verifier).unwrap();
        hello_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        stop.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let finished = worker.is_finished();
        done_tx.send(()).unwrap();
        server.join().unwrap();
        assert!(finished, "worker did not honor cancellation while server was silent");
        worker.join().unwrap();
        std::env::remove_var("WATCH_UNLOCK_PIPE");
    }
}

