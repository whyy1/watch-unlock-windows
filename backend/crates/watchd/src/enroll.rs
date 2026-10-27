use std::io::Write;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
};



pub(crate) fn clear_secret(value: &mut String) {
    let ptr = value.as_mut_ptr();
    for index in 0..value.len() {
        unsafe { std::ptr::write_volatile(ptr.add(index), 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

pub(crate) fn clear_bytes(value: &mut Vec<u8>) {
    for byte in value.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

fn matching_identity(password: &str) -> Option<(String, String)> {
    // The session supplies its SID-filtered MicrosoftAccount identity first.
    // Stop after success instead of trying this password against other aliases.
    first_matching_identity(crate::session::identity_candidates(),
        |username, domain| validate_password(username, domain, password))
}

fn first_matching_identity(
    candidates: Vec<(String, String)>,
    validate: impl Fn(&str, &str) -> bool,
) -> Option<(String, String)> {
    candidates.into_iter().find(|(username, domain)| validate(username, domain))
}

#[derive(Serialize, Deserialize)]
pub struct StoredCredential {
    version: u8,
    pub username: String,
    pub domain: String,
    pub password: String,
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE)?;
        let mut mode = Default::default();
        GetConsoleMode(h, &mut mode)?;
        SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT)?;
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        let _ = SetConsoleMode(h, mode);
        println!();
        if let Err(error) = read {
            clear_secret(&mut line);
            return Err(error.into());
        }
        let length = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(length);
        Ok(line)
    }
}

/// 用提交时完全相同的身份校验密码（LOGON32_LOGON_NETWORK，不产生交互登录）。
fn validate_password(username: &str, domain: &str, password: &str) -> bool {
    let wu: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let wd: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wp: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
    let mut token = HANDLE::default();
    unsafe {
        let authenticated = LogonUserW(
            PCWSTR(wu.as_ptr()),
            PCWSTR(wd.as_ptr()),
            PCWSTR(wp.as_ptr()),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
        .is_ok();
        for unit in &mut wp {
            std::ptr::write_volatile(unit, 0);
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // LogonCache can contain another user's MSA. Valid credentials alone
        // do not prove this is the interactive user being enrolled.
        let ok = authenticated && token_is_current_user(token);
        if !token.is_invalid() {
            let _ = CloseHandle(token);
        }
        ok
    }
}

pub(crate) fn token_user_buffer(token: HANDLE) -> Option<Vec<usize>> {
    let mut required = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut required);
        if required == 0 {
            return None;
        }
        // usize alignment is sufficient for TOKEN_USER and its trailing SID.
        let mut buffer = vec![0usize; (required as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()];
        GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), required, &mut required)
            .ok()?;
        Some(buffer)
    }
}

fn token_is_current_user(candidate: HANDLE) -> bool {
    unsafe {
        let mut current = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current).is_err() {
            return false;
        }
        let candidate_user = token_user_buffer(candidate);
        let current_user = token_user_buffer(current);
        let _ = CloseHandle(current);
        match (candidate_user, current_user) {
            (Some(candidate), Some(current)) => {
                let candidate = &*(candidate.as_ptr().cast::<TOKEN_USER>());
                let current = &*(current.as_ptr().cast::<TOKEN_USER>());
                EqualSid(candidate.User.Sid, current.User.Sid).is_ok()
            }
            _ => false,
        }
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) { clear_secret(&mut self.password); }
}

fn save_credential(record: &StoredCredential) -> anyhow::Result<std::path::PathBuf> {
    let clear = crate::vault::SecretBytes(serde_json::to_vec(record)?);
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA unavailable"))?;
    crate::vault::save_secret(&dir, "cred.blob", &clear.0)?;
    Ok(dir.join("cred.blob"))
}

/// Only unit tests can inject fake credentials. Release and development binaries cannot.
pub fn load_credential() -> Option<StoredCredential> {
    #[cfg(test)]
    if let Ok(password) = std::env::var("WATCH_UNLOCK_TEST_PASSWORD") {
        return Some(StoredCredential {
            version: 1, username: "TestUser".into(), domain: "TestDomain".into(), password,
        });
    }
    let dir = crate::config::app_dir()?;
    let clear = crate::vault::SecretBytes(crate::vault::load_secret(&dir, "cred.blob").ok()?);
    let record = serde_json::from_slice::<StoredCredential>(&clear.0).ok()?;
    (record.version == 1).then_some(record)
}

const WRONG_PASSWORD: &str = "密码验证失败。请填写本机登录账户的密码，不支持 PIN。如忘记密码，可点击「忘记密码？」查看重置方法。";

/// Validate against Windows and require the returned token to have the current user's SID.
pub fn enroll_password(password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!password.is_empty() && password.encode_utf16().count() <= 512
        && !password.contains('\0'), "Invalid Windows account password format");
    let (username, domain) = matching_identity(password)
        .ok_or(crate::bridge::Shown(WRONG_PASSWORD))?;
    let record = StoredCredential { version: 1, username, domain, password: password.to_owned() };
    save_credential(&record)?;
    Ok(())
}

pub fn clear_credential() -> anyhow::Result<()> {
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA unavailable"))?;
    crate::vault::delete_secret(&dir, "cred.blob")
}

pub fn credential_configured() -> bool {
    load_credential().is_some()
}
/// CLI enrollment; no password is accepted through command-line arguments or environment.
pub fn enroll() -> anyhow::Result<()> {
    let mut first = read_password("Windows account password: ")?;
    let second_result = read_password("Confirm password: ");
    let result = match second_result {
        Ok(mut second) => {
            let matches = first == second;
            clear_secret(&mut second);
            if matches { enroll_password(&first) } else { Err(anyhow::anyhow!("Passwords do not match")) }
        },
        Err(error) => Err(error),
    };
    clear_secret(&mut first);
    result?;
    println!("Account credential saved with CurrentUser DPAPI");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::first_matching_identity;

    #[test]
    fn successful_current_identity_stops_before_another_password_attempt() {
        let candidates = vec![("current@example.test".into(), "MicrosoftAccount".into()),
            ("local-alias".into(), "DESKTOP".into())];
        let result = first_matching_identity(candidates, |username, domain| {
            assert_eq!(username, "current@example.test");
            assert_eq!(domain, "MicrosoftAccount");
            true
        });
        assert_eq!(result, Some(("current@example.test".into(), "MicrosoftAccount".into())));
    }

    #[test]
    fn rejected_stale_alias_allows_the_next_current_user_candidate() {
        let candidates = vec![("stale@example.test".into(), "MicrosoftAccount".into()),
            ("current-local".into(), "DESKTOP".into())];
        let result = first_matching_identity(candidates, |username, _| username == "current-local");
        assert_eq!(result, Some(("current-local".into(), "DESKTOP".into())));
        assert!(first_matching_identity(Vec::new(), |_, _| panic!("no candidate to validate")).is_none());
    }
}
