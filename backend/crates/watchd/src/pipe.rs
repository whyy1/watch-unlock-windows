//! 命名管道：每条连接一次 hello / unlock，采用有上限的行式 JSON。
//! Peer identity is checked independently of the nonce. Only SYSTEM LogonUI may receive credentials.
//! A logon screen on the physical screen while this session is disconnected may also send small
//! `input` frames after its hello, because this session cannot see input there.

use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, RevertToSelf, TokenUser, WinLocalSystemSid,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, PIPE_ACCESS_DUPLEX, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
#[cfg(test)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientSessionId,
    GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// GetTickCount value of the last keyboard or mouse input on the console logon screen.
    /// Sent only by a logon screen in another session (see [`peer_session_allowed`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u32>,
}

impl Drop for PipeMsg {
    fn drop(&mut self) {
        if let Some(password) = self.password.as_mut() {
            crate::enroll::clear_secret(password);
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionId {
    epoch: u64,
    nonce: String,
}

pub enum PipeEvent {
    /// `console`: the logon screen sits in the console session while this session is
    /// disconnected. `input` is that screen's last keyboard or mouse tick, if it sent one.
    Hello { connection: ConnectionId, console: bool, input: Option<u32> },
    /// Later keyboard or mouse input on a console logon screen.
    Input(u32),
    Gone,
}

/// Where the logon screen that opened the pipe runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerSession {
    /// This session's own lock screen: the normal case.
    Own,
    /// The physical screen's logon screen while this session is disconnected (closed Remote
    /// Desktop, `tsdiscon`, switch user). Signing in there reconnects this session.
    Console,
}

/// Which logon screen may receive this session's credential. Normally only this session's own.
/// While this session is disconnected nobody sees its own lock screen; the one on the physical
/// screen is in the console session, and only an empty one (no user signed in there) is
/// accepted. A Remote Desktop logon screen is never the console session, so it never qualifies.
fn peer_session_allowed(own: u32, peer: u32, own_disconnected: bool, console: Option<u32>,
    peer_has_user: Option<bool>) -> Result<PeerSession, &'static str> {
    if !own_disconnected {
        return if peer == own { Ok(PeerSession::Own) } else { Err("pipe_session_mismatch") };
    }
    if peer == own { return Err("pipe_session_disconnected"); }
    if console == Some(peer) && peer_has_user == Some(false) { Ok(PeerSession::Console) }
    else { Err("pipe_session_mismatch") }
}

fn check_peer_session(peer: u32) -> Result<PeerSession, &'static str> {
    let own = session_id().map_err(|_| "pipe_session_mismatch")?;
    let disconnected = crate::session::current_session_disconnected();
    // Only looked up when they can matter, so the normal lock screen path stays as it was.
    let console = if disconnected { crate::session::console_session() } else { None };
    let peer_has_user = if disconnected && peer != own { crate::session::session_has_user(peer) } else { None };
    peer_session_allowed(own, peer, disconnected, console, peer_has_user)
}

/// Bytes after the hello: newline-terminated `input` frames only, each small.
const MAX_INPUT_BYTES: usize = 256;

/// Splits complete `input` frames off `pending`; anything else closes the connection.
fn take_inputs(pending: &mut Vec<u8>) -> Result<Vec<u32>, ()> {
    let mut ticks = Vec::new();
    while let Some(end) = pending.iter().position(|&byte| byte == b'\n') {
        let message: PipeMsg = serde_json::from_slice(&pending[..end]).map_err(|_| ())?;
        pending.drain(..=end);
        if message.msg != "input" || message.password.is_some() { return Err(()); }
        ticks.push(message.input.ok_or(())?);
    }
    if pending.len() > MAX_INPUT_BYTES { return Err(()); }
    Ok(ticks)
}

/// What one poll of the connection produced.
#[derive(Default)]
struct Polled {
    hello: bool,
    hello_input: Option<u32>,
    inputs: Vec<u32>,
}

pub struct UnlockGrant {
    connection: ConnectionId,
    valid_until: Instant,
}

impl UnlockGrant {
    pub fn new(connection: ConnectionId, valid_until: Instant) -> Self {
        Self { connection, valid_until }
    }

    fn permits(&self, connection: &ConnectionId, now: Instant, locked: bool) -> bool {
        locked && now < self.valid_until && self.connection == *connection
    }
}

pub enum PipeCommand {
    Unlock(UnlockGrant),
    Cancel,
}

/// Accumulate bytes so split JSON and split UTF-8 are both handled correctly.
struct FrameReader {
    bytes: Vec<u8>,
    complete: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
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
        if end + 1 != self.bytes.len() {
            return Err(());
        }
        self.complete = true;
        let result = serde_json::from_slice(&self.bytes[..end]).map_err(|_| ());
        crate::enroll::clear_bytes(&mut self.bytes);
        result.map(Some)
    }
}

impl Drop for FrameReader {
    fn drop(&mut self) {
        crate::enroll::clear_bytes(&mut self.bytes);
    }
}

struct PipeHandle(HANDLE);

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

fn session_id() -> windows::core::Result<u32> {
    let mut session = 0;
    unsafe { ProcessIdToSessionId(std::process::id(), &mut session)?; }
    Ok(session)
}

pub fn pipe_name() -> String {
    #[cfg(test)]
    if let Ok(name) = std::env::var("WATCH_UNLOCK_PIPE") {
        return format!("\\\\.\\pipe\\{name}");
    }
    format!("\\\\.\\pipe\\WatchUnlockWindows-{}", session_id().unwrap_or(0))
}

/// Records a handshake stage in the user-visible history, at most once a minute per stage,
/// because the provider retries every 100 ms. Fixed text only: no peer data or secrets.
fn diagnose(stage: &'static str, detail: &'static str) {
    static LAST: std::sync::Mutex<Vec<(&'static str, Instant)>> = std::sync::Mutex::new(Vec::new());
    let Ok(mut last) = LAST.lock() else { return };
    let now = Instant::now();
    if let Some((_, at)) = last.iter_mut().find(|(name, _)| *name == stage) {
        if now.duration_since(*at) < Duration::from_secs(60) { return; }
        *at = now;
    } else {
        last.push((stage, now));
    }
    drop(last);
    crate::audit::record(stage, None, detail);
}

fn is_win32_error(err: &windows::core::Error, code: u32) -> bool {
    (err.code().0 as u32 & 0xFFFF) == code
}

pub fn start_pipe_server(
    tx_events: Sender<PipeEvent>,
    rx_cmd: Receiver<PipeCommand>,
) -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("pipe-server".into())
        .spawn(move || pipe_loop(tx_events, rx_cmd))?;
    Ok(())
}

fn create_pipe(name: &str) -> windows::core::Result<PipeHandle> {
    create_pipe_with_sddl(name, "D:P(A;;GA;;;SY)")
}

fn create_pipe_with_sddl(name: &str, sddl: &str) -> windows::core::Result<PipeHandle> {
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let security: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    unsafe {
        // Production allows SYSTEM only. Same-session identity/path checks follow connection.
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(security.as_ptr()), SDDL_REVISION_1, &mut descriptor, None,
        )?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let handle = CreateNamedPipeW(
            PCWSTR(wname.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, MAX_FRAME_BYTES as u32, MAX_FRAME_BYTES as u32, 0, Some(&attributes),
        );
        // Preserve GetLastError before LocalFree can overwrite it.
        let result = if handle.is_invalid() {
            Err(windows::core::Error::from_win32())
        } else {
            Ok(PipeHandle(handle))
        };
        let _ = LocalFree(HLOCAL(descriptor.0));
        result
    }
}

fn client_is_system(pipe: HANDLE) -> bool {
    struct Revert;
    impl Drop for Revert { fn drop(&mut self) { unsafe { let _ = RevertToSelf(); } } }
    unsafe {
        if ImpersonateNamedPipeClient(pipe).is_err() { return false; }
        let _revert = Revert;
        let mut token = HANDLE::default();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).is_err() { return false; }
        let token = PipeHandle(token);
        let mut size = 0;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut size);
        let mut buffer = vec![0usize; (size as usize + 7) / std::mem::size_of::<usize>()];
        if GetTokenInformation(token.0, TokenUser, Some(buffer.as_mut_ptr().cast()), size, &mut size).is_err() {
            return false;
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool()
    }
}

/// Image name from a process snapshot, which needs no handle to the process itself.
fn process_name(pid: u32) -> Option<String> {
    unsafe {
        let snapshot = PipeHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?);
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        Process32FirstW(snapshot.0, &mut entry).ok()?;
        loop {
            if entry.th32ProcessID == pid {
                let length = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                return String::from_utf16(&entry.szExeFile[..length]).ok();
            }
            Process32NextW(snapshot.0, &mut entry).ok()?;
        }
    }
}

/// The trust boundary is the SYSTEM-only pipe DACL plus the impersonated SYSTEM token. A
/// medium-integrity daemon usually cannot open the SYSTEM LogonUI process, so the image is
/// identified by name and session from a snapshot; when the process can be opened, its full
/// System32 path is checked as well and the handle pins the PID.
fn authorized_logon_ui(pipe: HANDLE) -> Result<Option<PipeHandle>, &'static str> {
    if !client_is_system(pipe) { return Err("pipe_peer_not_system"); }
    unsafe {
        // ProcessIdToSessionId and OpenProcess are denied for SYSTEM processes from a normal
        // user process (verified against winlogon.exe). The client's session was already
        // checked through the pipe itself, and the name comes from a handle-free snapshot.
        let mut pid = 0;
        GetNamedPipeClientProcessId(pipe, &mut pid).map_err(|_| "pipe_peer_unknown")?;
        let name = process_name(pid).ok_or("pipe_peer_unknown")?;
        if !name.eq_ignore_ascii_case("LogonUI.exe") { return Err("pipe_peer_not_logonui"); }
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return Ok(None) };
        let process = PipeHandle(handle);
        let mut path = [0u16; 32768];
        let mut length = path.len() as u32;
        if QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut length).is_err() {
            return Ok(None);
        }
        let actual = String::from_utf16(&path[..length as usize]).map_err(|_| "pipe_peer_unknown")?;
        let system_length = GetSystemDirectoryW(Some(&mut path)) as usize;
        if system_length == 0 || system_length >= path.len() { return Err("pipe_peer_unknown"); }
        let expected = format!("{}\\LogonUI.exe", String::from_utf16(&path[..system_length]).map_err(|_| "pipe_peer_unknown")?);
        if actual.eq_ignore_ascii_case(&expected) { Ok(Some(process)) } else { Err("pipe_peer_not_logonui") }
    }
}

fn peer_detail(stage: &'static str) -> &'static str {
    match stage {
        "pipe_peer_not_system" => "握手方令牌不是 SYSTEM，已拒绝",
        "pipe_peer_not_logonui" => "握手方不是本会话的系统登录界面进程，已拒绝",
        _ => "无法识别握手方进程，已拒绝",
    }
}

struct Connection {
    pipe: PipeHandle,
    epoch: u64,
    connected_at: Option<Instant>,
    frame: FrameReader,
    nonce: Option<String>,
    /// Set once an unlock was written; the provider then disconnects normally.
    sent_unlock: bool,
    _peer_process: Option<PipeHandle>,
    /// The console session, when the logon screen is there rather than in this session.
    console_peer: Option<u32>,
    /// Unparsed bytes of `input` frames that follow a console logon screen's hello.
    inputs: Vec<u8>,
    #[cfg(test)]
    test_peer: bool,
}

impl Connection {
    fn new(pipe: PipeHandle) -> Self {
        static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
        Self { pipe, epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
            connected_at: None, frame: FrameReader::default(), nonce: None, sent_unlock: false,
            _peer_process: None, console_peer: None, inputs: Vec::new(), #[cfg(test)] test_peer: false }
    }

    /// A console logon screen keeps its claim only while this session stays disconnected and
    /// that session is still the one on the physical screen.
    fn peer_still_allowed(&self) -> bool {
        match self.console_peer {
            None => true,
            Some(peer) => check_peer_session(peer) == Ok(PeerSession::Console),
        }
    }

    fn id(&self) -> Option<ConnectionId> {
        self.nonce.as_ref().map(|nonce| ConnectionId { epoch: self.epoch, nonce: nonce.clone() })
    }

    #[cfg(test)]
    fn poll_hello(&mut self) -> Result<bool, ()> { self.poll().map(|polled| polled.hello) }

    fn poll(&mut self) -> Result<Polled, ()> {
        let handle = self.pipe.0;
        if self.connected_at.is_none() {
            match unsafe { ConnectNamedPipe(handle, None) } {
                Ok(()) => {},
                Err(error) if is_win32_error(&error, ERROR_PIPE_CONNECTED.0) => {},
                Err(error) if is_win32_error(&error, ERROR_PIPE_LISTENING.0) => return Ok(Polled::default()),
                Err(_) => return Err(()),
            }
            let mut peer_session = 0;
            if unsafe { GetNamedPipeClientSessionId(handle, &mut peer_session) }.is_err() {
                diagnose("pipe_session_mismatch", "登录组件来自其他会话，已拒绝");
                return Err(());
            }
            match check_peer_session(peer_session) {
                Ok(PeerSession::Own) => diagnose("pipe_client_connected", "登录组件已打开管道，等待握手"),
                Ok(PeerSession::Console) => {
                    self.console_peer = Some(peer_session);
                    diagnose("pipe_client_connected", "屏幕上的登录界面已打开管道（本会话已断开），等待握手");
                }
                // While disconnected this session's own, invisible lock screen may retry every
                // 100 ms for hours; it is refused without filling the history.
                Err("pipe_session_disconnected") => return Err(()),
                Err(_) => { diagnose("pipe_session_mismatch", "登录组件来自其他会话，已拒绝"); return Err(()); }
            }
            self.connected_at = Some(Instant::now());
        }
        if !self.frame.complete && self.connected_at.unwrap().elapsed() > HELLO_TIMEOUT {
            diagnose("pipe_hello_timeout", "登录组件已连接但未发送握手，可能未信任后台程序");
            return Err(());
        }
        let mut buffer = [0u8; 1024];
        let mut read = 0;
        let result = match unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut read), None) } {
            // Only a console logon screen may send anything after its hello: input frames. They
            // may still arrive after the unlock went out; closing then could discard it unread.
            Ok(_) if read > 0 && self.frame.complete => {
                if self.console_peer.is_none() { Err(()) } else {
                    self.inputs.extend_from_slice(&buffer[..read as usize]);
                    let inputs = take_inputs(&mut self.inputs);
                    clear_buffer(&mut buffer);
                    return inputs.map(|inputs| Polled { inputs, ..Default::default() });
                }
            },
            Ok(_) if read > 0 => self.frame.push(&buffer[..read as usize]),
            Err(error) if is_win32_error(&error, ERROR_NO_DATA.0) => Ok(None),
            _ => {
                // After a handshake or a delivered unlock this is the normal end of a logon screen.
                if self.nonce.is_none() && !self.sent_unlock {
                    diagnose("pipe_client_dropped", "登录组件连接后断开，未完成握手，可能未信任后台程序");
                }
                Err(())
            }
        };
        clear_buffer(&mut buffer);
        match result? {
            Some(mut message) if message.msg == "hello" => {
                // Identification impersonation is tied to the message just read.
                // No credentials or authorization leave the daemon before this succeeds.
                #[cfg(not(test))]
                {
                    match authorized_logon_ui(handle) {
                        Ok(peer) => self._peer_process = peer,
                        Err(stage) => { diagnose(stage, peer_detail(stage)); return Err(()); }
                    }
                }
                #[cfg(test)]
                if !self.test_peer { self._peer_process = authorized_logon_ui(handle).map_err(|_| ())?; }
                let nonce = message.nonce.take().filter(|nonce| valid_nonce(nonce)).ok_or(())?;
                self.nonce = Some(nonce);
                let hello_input = if self.console_peer.is_some() { message.input } else { None };
                Ok(Polled { hello: true, hello_input, inputs: Vec::new() })
            },
            Some(_) => Err(()),
            None => Ok(Polled::default()),
        }
    }

    fn send_unlock(&mut self, grant: UnlockGrant, commands: &Receiver<PipeCommand>) -> Result<(), ()> {
        let connection = self.id().ok_or(())?;
        let locked = crate::session::current_session_locked().unwrap_or(false);
        if !grant.permits(&connection, Instant::now(), locked) || !self.peer_still_allowed() { return Err(()); }
        // Consume authorization even on serialization or partial-write failures.
        let nonce = self.nonce.take().ok_or(())?;
        let Some(mut credential) = crate::enroll::load_credential() else {
            tracing::warn!("[PIPE] 未登记凭据，取消本次解锁");
            return Err(());
        };
        let message = PipeMsg {
            msg: "unlock".into(), nonce: None, echo: Some(nonce),
            password: Some(std::mem::take(&mut credential.password)),
            username: Some(std::mem::take(&mut credential.username)),
            domain: Some(std::mem::take(&mut credential.domain)),
            input: None,
        };
        let mut output = serde_json::to_vec(&message).map_err(|_| ())?;
        output.push(b'\n');
        let mut written = 0;
        // A cancellation received during DPAPI/serialization revokes this grant.
        // Any superseding queued grant also makes this old one unusable; commands
        // are never carried over to another handshake or Windows lock cycle.
        let locked = crate::session::current_session_locked().unwrap_or(false);
        let superseded = queue_revoked(commands);
        let success = output.len() <= MAX_FRAME_BYTES
            && !superseded && grant.permits(&connection, Instant::now(), locked) && self.peer_still_allowed()
            && unsafe { WriteFile(self.pipe.0, Some(&output), Some(&mut written), None) }.is_ok()
            && written as usize == output.len();
        crate::enroll::clear_bytes(&mut output);
        self.sent_unlock = success;
        if success { Ok(()) } else { Err(()) }
    }
}

fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty() && nonce.len() <= 128 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn queue_revoked(commands: &Receiver<PipeCommand>) -> bool {
    match commands.try_recv() {
        Err(TryRecvError::Empty) => false,
        Ok(_) | Err(TryRecvError::Disconnected) => true,
    }
}

fn clear_buffer(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn pipe_loop(tx_events: Sender<PipeEvent>, rx_cmd: Receiver<PipeCommand>) {
    let name = pipe_name();
    tracing::info!("[PIPE] 监听 {}", name);
    let mut connection: Option<Connection> = None;
    let mut last_console_check = Instant::now();
    loop {
        // A command is valid only for the currently handshaken connection.
        // Never preserve it across disconnects or failed writes.
        let mut unlock = None;
        loop {
            match rx_cmd.try_recv() {
                Ok(PipeCommand::Unlock(grant)) => {
                    unlock = connection.as_ref().and_then(Connection::id)
                        .filter(|connection| grant.permits(connection, Instant::now(), true)).map(|_| grant);
                },
                Ok(PipeCommand::Cancel) => unlock = None,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        if connection.is_none() {
            match create_pipe(&name) {
                Ok(pipe) => connection = Some(Connection::new(pipe)),
                Err(error) => {
                    diagnose("pipe_create_failed", "后台无法创建登录组件管道，5 秒后重试");
                    tracing::warn!("[PIPE] 创建失败: {error}，5s 后重试");
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            }
        }
        let peer = connection.as_mut().unwrap();
        let mut closed = false;
        // Once this session is back on a screen (signed in at the console, or Remote Desktop
        // reconnected), the console logon screen loses its claim and must free the single
        // pipe instance for this session's own lock screen. Checked once a second.
        if peer.console_peer.is_some() && last_console_check.elapsed() >= Duration::from_secs(1) {
            last_console_check = Instant::now();
            closed = !peer.peer_still_allowed();
        }
        let polled = if closed { Err(()) } else { peer.poll() };
        match polled {
            Ok(polled) => {
                if polled.hello {
                    if let Some(connection) = peer.id() {
                        let _ = tx_events.send(PipeEvent::Hello { connection,
                            console: peer.console_peer.is_some(), input: polled.hello_input });
                    }
                }
                for tick in polled.inputs { let _ = tx_events.send(PipeEvent::Input(tick)); }
            },
            Err(()) => closed = true,
        }
        if let Some(grant) = unlock.filter(|_| !closed) {
            if peer.send_unlock(grant, &rx_cmd).is_ok() {
                tracing::info!("[PIPE] 已发送一次 unlock");
            } else {
                tracing::warn!("[PIPE] unlock 失败，取消本次授权");
                closed = true;
            }
        }
        if closed {
            connection = None;
            let _ = tx_events.send(PipeEvent::Gone);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(FrameReader::default().push(b"{\"msg\":\"hello\"}\n{\"msg\":\"hello\"}\n").is_err());
    }

    #[test]
    fn only_the_own_session_or_an_empty_console_logon_screen_qualifies() {
        use PeerSession::*;
        // Normal lock screen: same session only, whatever the console is.
        assert_eq!(peer_session_allowed(1, 1, false, Some(1), None), Ok(Own));
        assert_eq!(peer_session_allowed(1, 2, false, Some(2), Some(false)), Err("pipe_session_mismatch"));
        // Disconnected (closed Remote Desktop, tsdiscon): the empty logon screen on the physical screen.
        assert_eq!(peer_session_allowed(1, 2, true, Some(2), Some(false)), Ok(Console));
        // Its own invisible lock screen must not hold the single pipe instance.
        assert_eq!(peer_session_allowed(1, 1, true, Some(2), None), Err("pipe_session_disconnected"));
        // A Remote Desktop logon screen is not the console session.
        assert_eq!(peer_session_allowed(1, 3, true, Some(2), Some(false)), Err("pipe_session_mismatch"));
        // Another user signed in on the physical screen, or Windows cannot say.
        assert_eq!(peer_session_allowed(1, 2, true, Some(2), Some(true)), Err("pipe_session_mismatch"));
        assert_eq!(peer_session_allowed(1, 2, true, Some(2), None), Err("pipe_session_mismatch"));
        assert_eq!(peer_session_allowed(1, 2, true, None, Some(false)), Err("pipe_session_mismatch"));
    }

    #[test]
    fn input_frames_carry_only_a_tick() {
        let mut pending = b"{\"msg\":\"input\",\"input\":42}\n{\"msg\":\"input\",\"input\":43}\n{\"msg\":\"in".to_vec();
        assert_eq!(take_inputs(&mut pending), Ok(vec![42, 43]));
        assert_eq!(pending, b"{\"msg\":\"in");
        pending.extend_from_slice(b"put\",\"input\":44}\n");
        assert_eq!(take_inputs(&mut pending), Ok(vec![44]));
        for bad in [&b"{\"msg\":\"hello\",\"nonce\":\"01\"}\n"[..], b"{\"msg\":\"input\"}\n",
            b"{\"msg\":\"input\",\"input\":1,\"password\":\"x\"}\n", b"not-json\n"] {
            assert!(take_inputs(&mut bad.to_vec()).is_err());
        }
        assert!(take_inputs(&mut vec![b'a'; MAX_INPUT_BYTES + 1]).is_err());
        // The unlock frame stays exactly as before: no input field on the wire.
        let unlock = PipeMsg { msg: "unlock".into(), nonce: None, echo: None, password: None,
            username: None, domain: None, input: None };
        assert!(!serde_json::to_string(&unlock).unwrap().contains("input"));
    }

    #[test]
    fn nonce_must_be_bounded_nonempty_hex() {
        assert!(valid_nonce("0123456789abcdef"));
        assert!(!valid_nonce(""));
        assert!(!valid_nonce("not-hex"));
        assert!(!valid_nonce(&"a".repeat(129)));
    }

    #[test]
    fn grant_binds_the_exact_handshake_connection_and_absolute_deadline() {
        let now = Instant::now();
        let current = ConnectionId { epoch: 1, nonce: "a".repeat(64) };
        let grant = UnlockGrant::new(current.clone(), now + Duration::from_millis(100));
        assert!(grant.permits(&current, now, true));
        assert!(!grant.permits(&current, now, false));
        assert!(!grant.permits(&current, now + Duration::from_millis(100), true));
        assert!(!grant.permits(&current, now + Duration::from_secs(5), true));
        let wrong_nonce = ConnectionId { epoch: 1, nonce: "b".repeat(64) };
        assert!(!grant.permits(&wrong_nonce, now, true));
        // Even an accidental repeated provider nonce cannot reuse a queued grant
        // after disconnect/reconnect, because the server's epoch changes too.
        let reconnected = ConnectionId { epoch: 2, ..current };
        assert!(!grant.permits(&reconnected, now, true));
    }

    #[test]
    fn cancellation_or_lost_runtime_during_credential_loading_revokes_the_grant() {
        let (sender, receiver) = std::sync::mpsc::channel();
        assert!(!queue_revoked(&receiver));
        sender.send(PipeCommand::Cancel).unwrap();
        assert!(queue_revoked(&receiver));
        let connection = ConnectionId { epoch: 1, nonce: "a".repeat(64) };
        sender.send(PipeCommand::Unlock(UnlockGrant::new(connection,
            Instant::now() + Duration::from_secs(1)))).unwrap();
        assert!(queue_revoked(&receiver));
        drop(sender);
        assert!(queue_revoked(&receiver));
    }

    #[test]
    fn normal_user_cannot_open_production_credential_pipe() {
        let name = format!("\\\\.\\pipe\\WatchUnlockWindows-Restricted-Test-{}", std::process::id());
        let _server = create_pipe(&name).unwrap();
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let result = unsafe { CreateFileW(PCWSTR(wide.as_ptr()), FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0), None, OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None) };
        if let Ok(handle) = result {
            unsafe { let _ = CloseHandle(handle); }
            panic!("test must run as a regular user, who must not receive credential-pipe access");
        }
    }

    #[test]
    fn first_instance_is_exclusive_and_same_session_hello_works() {
        let name = format!("\\\\.\\pipe\\WatchUnlock-Server-Test-{}", std::process::id());
        let server = create_pipe_with_sddl(&name, "D:P(A;;GA;;;SY)(A;;GA;;;OW)").unwrap();
        assert!(create_pipe_with_sddl(&name, "D:P(A;;GA;;;SY)(A;;GA;;;OW)").is_err(), "second server must not join the pipe name");
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let client = PipeHandle(unsafe {
            CreateFileW(PCWSTR(wide.as_ptr()), FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0), None, OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None).unwrap()
        });
        let mut connection = Connection::new(server);
        connection.test_peer = true;
        assert!(!connection.poll_hello().unwrap());
        for fragment in [b"{\"msg\":\"hello\",\"nonce\":\"01".as_slice(), b"23\"}\n".as_slice()] {
            let mut written = 0;
            unsafe { WriteFile(client.0, Some(fragment), Some(&mut written), None) }.unwrap();
            assert_eq!(written as usize, fragment.len());
        }
        assert!(connection.poll_hello().unwrap());
        assert_eq!(connection.nonce.as_deref(), Some("0123"));
        assert!(!connection.poll_hello().unwrap(), "hello must be delivered once");
    }
}
