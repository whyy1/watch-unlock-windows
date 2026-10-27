//! Public device metadata and separate encrypted secrets.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
use watch_unlock_domain::DevicePolicy;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub adapter: String,
    pub near_rssi: i16,
    pub far_rssi: i16,
    /// Seamless unlock: a far-then-near return unlocks at once. When false, the return waits
    /// for keyboard or mouse input on the lock screen. The key name predates this option.
    pub auto_unlock_on_return: bool,
    pub enabled: bool,
    /// Windows identity address of the bound watch ("AA:BB:CC:DD:EE:FF"). Public metadata, not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Seconds a far-then-near return stays usable while the logon UI appears.
    #[serde(default = "default_return_window")]
    pub return_window_seconds: u16,
}

pub const RETURN_WINDOW_SECONDS: std::ops::RangeInclusive<u16> = 5..=120;

pub fn default_return_window() -> u16 { 30 }

impl Device {
    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id) || self.name.trim().is_empty() || self.name.len() > 240
            || self.name.chars().any(char::is_control) || self.adapter != "apple-ble" {
            bail!("Invalid device metadata");
        }
        if let Some(address) = &self.address {
            if !valid_address(address) { bail!("Invalid device address"); }
        }
        if !RETURN_WINDOW_SECONDS.contains(&self.return_window_seconds) { bail!("Invalid return window"); }
        if !(-100..=-20).contains(&self.near_rssi) || !(-110..=-25).contains(&self.far_rssi)
            || self.far_rssi >= self.near_rssi {
            bail!("Invalid near/far RSSI thresholds");
        }
        Ok(())
    }

    pub fn return_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.return_window_seconds.into())
    }

    pub fn policy(&self) -> DevicePolicy {
        DevicePolicy { near_rssi: self.near_rssi, far_rssi: self.far_rssi }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
// Unknown fields are tolerated so files written by the removed watch-confirmation feature still
// load; `remove_legacy_confirmation` rewrites them without those fields.
#[serde(default)]
pub struct Notifications {
    pub endpoint: String,
    pub enabled: bool,
    /// Push a notice after an unlock this app submitted.
    pub notify_on_unlock: bool,
}

impl Default for Notifications {
    fn default() -> Self {
        Self { endpoint: "https://api.day.app/push".into(), enabled: false, notify_on_unlock: true }
    }
}

pub fn data_dir() -> Result<PathBuf> {
    crate::config::app_dir().context("Local application data unavailable")
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Canonical colon-separated uppercase Bluetooth address, e.g. "C0:FF:EE:00:11:22".
pub fn valid_address(value: &str) -> bool {
    value.len() == 17 && value.split(':').count() == 6
        && value.split(':').all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)))
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0u8; bytes];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok()?; }
    Ok(hex::encode(random))
}

pub fn load_devices() -> Result<Vec<Device>> {
    let path = data_dir()?.join("devices.json");
    if !path.exists() { return Ok(Vec::new()); }
    let devices: Vec<Device> = read_json(&path)?;
    if devices.len() > 16 { bail!("Too many devices"); }
    for (index, device) in devices.iter().enumerate() {
        device.validate()?;
        if devices[..index].iter().any(|d| d.id == device.id) { bail!("Duplicate device"); }
    }
    Ok(devices)
}

pub fn save_devices(devices: &[Device]) -> Result<()> {
    if devices.len() > 16 { bail!("Too many devices"); }
    for device in devices { device.validate()?; }
    write_json("devices.json", devices)
}

pub fn load_identity(id: &str) -> Result<[u8; 16]> {
    if !valid_id(id) { bail!("Invalid device ID"); }
    let mut clear = crate::vault::load_secret(&data_dir()?, &format!("device-{id}.dpapi"))?;
    let result = clear.as_slice().try_into().map_err(|_| anyhow::anyhow!("Invalid identity"));
    crate::enroll::clear_bytes(&mut clear);
    result
}

pub fn identity_configured(id: &str) -> bool {
    match load_identity(id) {
        Ok(mut identity) => { crate::vault::erase(&mut identity); true }
        Err(_) => false,
    }
}

/// Read only the file explicitly selected by the user. Never changes source ACLs.
pub fn import_identity(path: &Path) -> Result<[u8; 16]> {
    use std::io::Read;
    use std::os::windows::fs::MetadataExt;
    if !path.is_absolute() || !path.extension().is_some_and(|extension|
        extension.eq_ignore_ascii_case("dpapi") || extension.eq_ignore_ascii_case("blob")) {
        bail!("Select an absolute encrypted identity file");
    }
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 || metadata.file_attributes() & 0x400 != 0 {
        bail!("Invalid encrypted identity file");
    }
    let mut encrypted = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut encrypted)?;
    if encrypted.len() > 64 * 1024 { bail!("Encrypted identity file too large"); }
    let clear = crate::vault::SecretBytes(crate::vault::unprotect(&encrypted)?);
    clear.0.as_slice().try_into().map_err(|_|anyhow::anyhow!("Identity file must decrypt to exactly 16 bytes"))
}

/// Settings for this PC rather than for one watch.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// Keep scanning with the lid closed, for laptops used shut with an external monitor.
    /// Off by default: closing the lid then stops scanning until it is opened again.
    pub scan_with_lid_closed: bool,
}

pub fn load_settings() -> Result<Settings> {
    let path = data_dir()?.join("settings.json");
    if !path.exists() { return Ok(Settings::default()); }
    read_json(&path)
}

pub fn load_notifications() -> Result<Notifications> {
    let path = data_dir()?.join("notifications.json");
    if !path.exists() { return Ok(Notifications::default()); }
    read_json(&path)
}

/// Deletes what the removed watch-confirmation feature stored: its relay token and the relay
/// URL inside notifications.json. Safe to call on every start.
pub fn remove_legacy_confirmation() -> Result<()> {
    let dir = data_dir()?;
    crate::vault::delete_secret(&dir, "computer-secret.dpapi")?;
    // The relay script kept its tokens and log here. remove_dir_all does not follow links.
    let relay = dir.join("relay");
    if std::fs::symlink_metadata(&relay).is_ok_and(|metadata| metadata.is_dir()) {
        std::fs::remove_dir_all(&relay).context("Cannot remove the old relay state")?;
    }
    let path = dir.join("notifications.json");
    if path.exists() {
        let raw: serde_json::Value = read_json(&path)?;
        if raw.get("confirmation_url").is_some() {
            write_json("notifications.json", &serde_json::from_value::<Notifications>(raw)?)?;
        }
    }
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::vault::ensure_private_file(path)?;
    let bytes = crate::vault::read_limited_file(path, 128 * 1024)?;
    serde_json::from_slice(&bytes).context("Invalid metadata")
}

/// The only metadata files the app writes. Every new settings file must be added here.
fn metadata_file(name: &str) -> bool {
    matches!(name, "devices.json" | "notifications.json" | "settings.json" | "status.json")
}

pub fn write_json<T: Serialize + ?Sized>(name: &str, value: &T) -> Result<()> {
    if !metadata_file(name) {
        bail!("Invalid metadata filename");
    }
    let dir = data_dir()?;
    crate::vault::ensure_private_dir(&dir)?;
    let temp = dir.join(format!("write-{}.tmp", random_hex(16)?));
    let result = (|| -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        drop(file);
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
        use std::os::windows::ffi::OsStrExt;
        let source = wide(&temp);
        let dest = wide(&dir.join(name));
        unsafe { MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(dest.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)?; }
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(temp); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_the_app_writes_is_an_allowed_metadata_file() {
        for name in ["devices.json", "notifications.json", "settings.json", "status.json"] {
            assert!(metadata_file(name), "{name}");
        }
        for name in ["cred.blob", "../devices.json", "settings.json.tmp", ""] {
            assert!(!metadata_file(name), "{name}");
        }
    }

    #[test]
    fn identifiers_cannot_escape_secret_directory() {
        assert!(valid_id(&"a".repeat(32)));
        for id in ["../cred.blob", "", "ABCDEF1234567890ABCDEF1234567890"] {
            assert!(!valid_id(id));
        }
    }
}
