//! Notifications are informational; delivery or opening a URL never authorizes unlock.

use std::io::Read;

use anyhow::{ensure, Result};
use serde::Deserialize;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts, SECURITY_FLAG_IGNORE_CERT_CN_INVALID,
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE,
    SECURITY_FLAG_IGNORE_UNKNOWN_CA, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_FLAG_SECURE, WINHTTP_INTERNET_SCHEME_HTTP, WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURITY_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};

const MAX_RESPONSE: usize = 4096;
const MAX_CONFIG: u64 = 16 * 1024;
// A test click waits on these, so an unreachable server must fail within a few seconds.
const CONNECT_TIMEOUT_MS: i32 = 3_000;
const TIMEOUT_MS: i32 = 5_000;

/// Why a notification did not go out. Only these fixed categories leave this module: never the
/// key, the endpoint or a system error text. `Network` carries the WinHTTP error number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    NotSaved,
    Disabled,
    InvalidEndpoint,
    InvalidKey,
    Network(u32),
    Rejected(u16),
}

impl Failure {
    pub fn code(self) -> String {
        match self {
            Self::NotSaved => "not_saved".into(),
            Self::Disabled => "disabled".into(),
            Self::InvalidEndpoint => "invalid_endpoint".into(),
            Self::InvalidKey => "invalid_key".into(),
            Self::Network(error) => format!("network_{error}"),
            Self::Rejected(status) => format!("rejected_{status}"),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSaved => formatter.write_str("还没有保存 Bark 设置，请先填写设备密钥并保存。"),
            Self::Disabled => formatter.write_str("通知未启用。"),
            Self::InvalidEndpoint => formatter.write_str("推送地址无效，需要以 http:// 或 https:// 开头。"),
            Self::InvalidKey => formatter.write_str("保存的 Bark 设备密钥格式不对，请重新填写并保存。"),
            Self::Network(ERROR_TIMEOUT) => formatter.write_str("请求超时，推送服务器没有响应。"),
            Self::Network(ERROR_NAME_NOT_RESOLVED) => formatter.write_str("请求失败，无法解析推送服务器的域名。"),
            Self::Network(ERROR_CANNOT_CONNECT) => formatter.write_str("请求失败，无法连接推送服务器。"),
            Self::Network(ERROR_SECURE_FAILURE) => formatter.write_str("请求失败，HTTPS 证书或加密协商未通过。"),
            Self::Network(error) => write!(formatter, "请求失败，推送服务器没有响应（WinHTTP 错误 {error}）。"),
            Self::Rejected(400) => formatter.write_str("推送服务器拒绝了请求（400），通常是设备密钥不对。"),
            Self::Rejected(status) => write!(formatter, "推送服务器返回错误（{status}）。"),
        }
    }
}

impl std::error::Error for Failure {}

const ERROR_TIMEOUT: u32 = 12002;
const ERROR_NAME_NOT_RESOLVED: u32 = 12007;
const ERROR_CANNOT_CONNECT: u32 = 12029;
const ERROR_SECURE_FAILURE: u32 = 12175;
const MAX_EXCERPT: usize = 200;

/// A failed send, with what the server answered when it answered at all.
struct Unsent { failure: Failure, response: Option<String> }

impl From<Failure> for Unsent {
    fn from(failure: Failure) -> Self { Self { failure, response: None } }
}

/// What the server answered, for the history: Bark's `message` when it sent JSON, otherwise the
/// start of the body. The key is masked in case a server echoes it back.
fn response_excerpt(status: u32, body: &[u8], key: &str) -> String {
    let text = String::from_utf8_lossy(body);
    let message = serde_json::from_str::<serde_json::Value>(&text).ok()
        .and_then(|value| value.get("message").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_else(|| text.into_owned());
    let message = if key.is_empty() { message } else { message.replace(key, "***") };
    let clean: String = message.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_EXCERPT).collect();
    let clean = clean.trim();
    if clean.is_empty() { format!("HTTP {status}，响应为空") } else { format!("HTTP {status}，响应：{clean}") }
}
#[derive(Deserialize)]
struct NotificationConfig {
    endpoint: String,
    enabled: bool,
    #[serde(default = "default_true")]
    notify_on_unlock: bool,
}

fn default_true() -> bool { true }

fn valid_key(key: &str) -> bool {
    (8..=256).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Host, port and path+query of a URL that passed `valid_url`.
struct Target { host: Vec<u16>, port: u16, object: Vec<u16>, secure: bool, ip: bool }

fn crack(url: &str) -> Option<Target> {
    // Self-hosted Bark servers are often plain HTTP on a LAN address, so both schemes are allowed.
    let lower = url.to_ascii_lowercase();
    let start = if lower.starts_with("https://") { 8 } else if lower.starts_with("http://") { 7 } else { return None };
    if url.len() > 2048 || url.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '#')) {
        return None;
    }
    let authority = url[start..].split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(['@', '%']) { return None; }
    let wide: Vec<u16> = url.encode_utf16().collect();
    let mut parts = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        dwHostNameLength: u32::MAX, dwUserNameLength: u32::MAX, dwPasswordLength: u32::MAX,
        dwUrlPathLength: u32::MAX, dwExtraInfoLength: u32::MAX, ..Default::default()
    };
    unsafe { WinHttpCrackUrl(&wide, 0, &mut parts) }.ok()?;
    let secure = parts.nScheme == WINHTTP_INTERNET_SCHEME_HTTPS;
    if !(secure || parts.nScheme == WINHTTP_INTERNET_SCHEME_HTTP) || parts.dwHostNameLength == 0
        || parts.dwUserNameLength != 0 || parts.dwPasswordLength != 0 {
        return None;
    }
    // The cracked fields point into `wide`, which is still alive here.
    let slice = |pointer: windows::core::PWSTR, length: u32| -> Vec<u16> {
        if pointer.is_null() || length == 0 { return Vec::new(); }
        unsafe { std::slice::from_raw_parts(pointer.0, length as usize).to_vec() }
    };
    let mut host = slice(parts.lpszHostName, parts.dwHostNameLength);
    let ip = ip_host(&String::from_utf16_lossy(&host));
    host.push(0);
    let mut object = slice(parts.lpszUrlPath, parts.dwUrlPathLength);
    if object.is_empty() { object.push(u16::from(b'/')); }
    object.extend(slice(parts.lpszExtraInfo, parts.dwExtraInfoLength));
    object.push(0);
    Some(Target { host, port: parts.nPort, object, secure, ip })
}

/// A server addressed by IP cannot hold a publicly trusted certificate, which is how people
/// self-host Bark. Only such hosts skip certificate checks; a host name is always verified.
fn ip_host(host: &str) -> bool {
    host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()
}

fn valid_url(url: &str) -> bool { crack(url).is_some() }

fn load_config() -> Result<NotificationConfig, Failure> {
    let dir = crate::config::app_dir().ok_or(Failure::NotSaved)?;
    crate::vault::ensure_private_dir(&dir).map_err(|_| Failure::NotSaved)?;
    let mut bytes = Vec::new();
    std::fs::File::open(dir.join("notifications.json")).map_err(|_| Failure::NotSaved)?
        .take(MAX_CONFIG + 1).read_to_end(&mut bytes).map_err(|_| Failure::NotSaved)?;
    if bytes.len() as u64 > MAX_CONFIG { return Err(Failure::NotSaved); }
    let config: NotificationConfig = serde_json::from_slice(&bytes).map_err(|_| Failure::NotSaved)?;
    if !valid_url(&config.endpoint) { return Err(Failure::InvalidEndpoint); }
    Ok(config)
}

pub fn validate_url(value: &str) -> Result<()> {
    ensure!(valid_url(value), "URL must use HTTP or HTTPS without user information or fragments");
    Ok(())
}

/// Bark answers HTTP 200 with `{"code":200}`; anything else is a rejection with that status.
fn check_response(status: u32, body: &[u8]) -> Result<(), Failure> {
    let code = serde_json::from_slice::<serde_json::Value>(body).ok()
        .and_then(|value| value.get("code").and_then(|code| code.as_i64()));
    match (status, code) {
        (200, Some(200)) => Ok(()),
        (200, Some(code)) => Err(Failure::Rejected(u16::try_from(code).unwrap_or(0))),
        (200, None) => Err(Failure::Rejected(200)),
        (status, _) => Err(Failure::Rejected(u16::try_from(status).unwrap_or(0))),
    }
}

/// Closes a WinHTTP handle when dropped.
struct Handle(*mut core::ffi::c_void);
impl Drop for Handle {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { let _ = WinHttpCloseHandle(self.0); } } }
}

/// One HTTP(S) POST through WinHTTP. AUTOMATIC_PROXY follows the Windows proxy settings, which
/// curl did not, so networks that require a proxy work too. Redirects are refused.
fn post(target: &Target, payload: &[u8], key: &str) -> Result<(), Unsent> {
    let network = |_| Unsent::from(Failure::Network(unsafe { GetLastError().0 }));
    unsafe {
        let session = Handle(WinHttpOpen(w!("WatchUnlock"), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(), PCWSTR::null(), 0));
        if session.0.is_null() { return Err(Failure::Network(GetLastError().0).into()); }
        WinHttpSetTimeouts(session.0, CONNECT_TIMEOUT_MS, CONNECT_TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS).map_err(network)?;
        let connection = Handle(WinHttpConnect(session.0, PCWSTR(target.host.as_ptr()), target.port, 0));
        if connection.0.is_null() { return Err(Failure::Network(GetLastError().0).into()); }
        let request = Handle(WinHttpOpenRequest(connection.0, w!("POST"), PCWSTR(target.object.as_ptr()),
            PCWSTR::null(), PCWSTR::null(), std::ptr::null(), if target.secure { WINHTTP_FLAG_SECURE } else { Default::default() }));
        if request.0.is_null() { return Err(Failure::Network(GetLastError().0).into()); }
        let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes();
        WinHttpSetOption(Some(request.0), WINHTTP_OPTION_REDIRECT_POLICY, Some(&never)).map_err(network)?;
        if target.secure && target.ip {
            let ignore = (SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE).to_ne_bytes();
            WinHttpSetOption(Some(request.0), WINHTTP_OPTION_SECURITY_FLAGS, Some(&ignore)).map_err(network)?;
        }
        let headers: Vec<u16> = "Content-Type: application/json\r\n".encode_utf16().collect();
        let length = u32::try_from(payload.len()).map_err(|_| Unsent::from(Failure::Network(0)))?;
        if WinHttpSendRequest(request.0, Some(&headers), Some(payload.as_ptr().cast()), length, length, 0).is_err()
            || WinHttpReceiveResponse(request.0, std::ptr::null_mut()).is_err() {
            let error = GetLastError().0;
            tracing::warn!("[NOTIFY] transport error {error}");
            return Err(Failure::Network(error).into());
        }
        let mut status = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(request.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, PCWSTR::null(),
            Some((&mut status as *mut u32).cast()), &mut size, std::ptr::null_mut()).map_err(network)?;
        let mut body = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(request.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut read).map_err(network)?;
            if read == 0 { break; }
            body.extend_from_slice(&chunk[..read as usize]);
            if body.len() > MAX_RESPONSE { break; }
        }
        check_response(status, &body).map_err(|failure| Unsent { failure, response: Some(response_excerpt(status, &body, key)) })
    }
}

/// Sends with the saved endpoint and key. `require_enabled` is false only for the explicit test,
/// so a test works before the user turns notifications on.
fn send(title: &str, body: &str, require_enabled: bool) -> Result<(), Unsent> {
    let config = load_config()?;
    if require_enabled && !config.enabled { return Err(Failure::Disabled.into()); }
    let target = crack(&config.endpoint).ok_or(Failure::InvalidEndpoint)?;
    let dir = crate::config::app_dir().ok_or(Failure::NotSaved)?;
    let key = crate::vault::SecretBytes(crate::vault::load_secret(&dir, "bark-key.dpapi").map_err(|_| Failure::NotSaved)?);
    let key_text = std::str::from_utf8(&key.0).unwrap_or("").trim();
    if !valid_key(key_text) { return Err(Failure::InvalidKey.into()); }
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        device_key: &'a str, title: &'a str, body: &'a str, group: &'static str,
        #[serde(rename = "isArchive")]
        is_archive: &'static str,
    }
    let payload = crate::vault::SecretBytes(serde_json::to_vec(&Payload {
        device_key: key_text, title, body, group: "watch-unlock-windows", is_archive: "0",
    }).map_err(|_| Failure::InvalidKey)?);
    post(&target, &payload.0, key_text)
}

fn record_failure(unsent: &Unsent) {
    let failure = unsent.failure;
    let response = unsent.response.as_deref().map(|text| format!("；{text}")).unwrap_or_default();
    crate::audit::record("notification_failed", None, &format!("通知未发出：{failure}（{}）{response}", failure.code()));
}

pub fn notify_unlock_async() {
    std::thread::spawn(|| {
        if !load_config().is_ok_and(|config| config.enabled && config.notify_on_unlock) { return; }
        if let Err(unsent) = send("已靠近解锁 Windows", "你回到电脑旁，手表靠近后已解锁。", true) {
            record_failure(&unsent);
        }
    });
}

/// Sends a test with the saved settings, whether or not notifications are switched on.
pub fn notify_test() -> Result<(), Failure> {
    send("Watch Unlock 测试通知", "这是一条测试通知，不会授予任何解锁权限。", false).map_err(|unsent| {
        record_failure(&unsent);
        unsent.failure
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_rejects_ambiguous_and_credential_urls() {
        for url in ["ftp://example.test/push", "http://user@example.test", "https://user@example.test", "https://user:password@example.test",
            "https://example.test/#fragment", "https://example.test\\@host", "https://example.test\r\nHeader:x", "https://"] {
            assert!(!valid_url(url), "unsafe URL accepted");
        }
        assert!(valid_url("https://example.test:8443/push"));
        assert!(valid_url("https://api.day.app/push"));
        assert!(valid_url("http://192.168.1.10:8080/push"));
    }

    #[test]
    fn cracked_target_keeps_host_port_path_and_query() {
        let target = crack("https://example.test:8443/push?group=a").unwrap();
        assert_eq!(String::from_utf16_lossy(&target.host), "example.test\0");
        assert_eq!(target.port, 8443);
        assert_eq!(String::from_utf16_lossy(&target.object), "/push?group=a\0");
        let bare = crack("https://api.day.app").unwrap();
        assert_eq!(bare.port, 443);
        assert_eq!(String::from_utf16_lossy(&bare.object), "/\0");
        assert!(bare.secure);
        let plain = crack("http://192.168.1.10/push").unwrap();
        assert_eq!(plain.port, 80);
        assert!(!plain.secure);
    }

    #[test]
    fn only_ip_addressed_servers_skip_certificate_checks() {
        assert!(!target_ip("https://api.day.app/push"));
        assert!(!target_ip("https://bark.example.com:8443/push"));
        assert!(!target_ip("https://192.168.1.10.example.com/push"));
        assert!(target_ip("https://192.168.1.10:8080/push"));
        assert!(target_ip("https://[fd00::1]:8443/push"));
    }

    fn target_ip(url: &str) -> bool { crack(url).unwrap().ip }

    #[test]
    fn provider_acceptance_requires_http_and_json_success() {
        assert_eq!(check_response(200, b"{\"code\":200}"), Ok(()));
        assert_eq!(check_response(302, b"{\"code\":200}"), Err(Failure::Rejected(302)));
        assert_eq!(check_response(200, b"{\"code\":400}"), Err(Failure::Rejected(400)));
        assert_eq!(check_response(400, b"{\"code\":400}"), Err(Failure::Rejected(400)));
        assert_eq!(check_response(200, b"{}"), Err(Failure::Rejected(200)));
    }

    #[test]
    fn failure_messages_name_the_cause_without_secrets() {
        assert_eq!(Failure::Rejected(400).code(), "rejected_400");
        assert!(Failure::Network(ERROR_TIMEOUT).to_string().contains("超时"));
        assert_eq!(Failure::Network(12029).code(), "network_12029");
        assert!(Failure::Network(12152).to_string().contains("12152"));
        assert!(Failure::NotSaved.to_string().contains("保存"));
        assert!(Failure::Rejected(500).to_string().contains("500"));
    }

    #[test]
    fn response_excerpt_prefers_the_bark_message_and_masks_the_key() {
        assert_eq!(response_excerpt(200, br#"{"code":400,"message":"device key_abc12345 not found"}"#, "key_abc12345"),
            "HTTP 200，响应：device *** not found");
        assert_eq!(response_excerpt(502, b"Bad\r\nGateway", ""), "HTTP 502，响应：Bad  Gateway");
        assert_eq!(response_excerpt(500, b"", "k"), "HTTP 500，响应为空");
        assert_eq!(response_excerpt(500, "长".repeat(500).as_bytes(), "").chars().count(), "HTTP 500，响应：".chars().count() + MAX_EXCERPT);
    }

    #[test]
    fn key_format_rejects_urls_and_whitespace() {
        assert!(valid_key("test_key-1234"));
        assert!(!valid_key("https://example.test/key"));
        assert!(!valid_key("has space"));
    }
}
