use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Snapshot,
    History,
    SaveDevice { device: DeviceInput },
    RemoveDevice { id: String },
    SaveNotifications {
        endpoint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        device_key: Option<String>,
        enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        notify_on_unlock: Option<bool>,
    },
    SaveCredential { password: String },
    SaveSettings { scan_with_lid_closed: bool },
    ClearCredential,
    PairedDevices,
    BindPaired { address: String, name: String },
    ClearHistory,
    NotifyTest,
    Diagnostics,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    adapter: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    irk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    irk_blob_path: Option<String>,
    near_rssi: i16,
    far_rssi: i16,
    auto_unlock_on_return: bool,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_window_seconds: Option<u16>,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Same canonical form as the backend's `registry::valid_address`: "AA:BB:CC:DD:EE:FF".
fn address_format(value: &str) -> bool {
    value.len() == 17 && value.split(':').count() == 6
        && value.split(':').all(|part| part.len() == 2
            && part.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)))
}

fn lower_hex(value: &str, length: usize) -> bool {
    hex(value, length) && !value.bytes().any(|b| b.is_ascii_uppercase())
}

fn web_url(value: &str) -> bool {
    let start = match value.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("https://") => 8,
        _ if value.get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://")) => 7,
        _ => return false,
    };
    bounded(value, 2048)
        && !value.chars().any(|c| c.is_whitespace() || matches!(c, '\\' | '#'))
        && !value[start..].split(['/', '?']).next().unwrap_or("").contains(['@', '%'])
        && url::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
            && url.username().is_empty() && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn identity_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    bounded(value, 4096) && path.is_absolute() && path.extension().is_some_and(|extension|
        extension.eq_ignore_ascii_case("dpapi") || extension.eq_ignore_ascii_case("blob"))
}

impl Request {
    /// How long the UI waits for the backend. Binding waits for UAC plus a 30 s scan and the
    /// backend gives up after 180 s, so the UI must outlast it instead of killing it midway.
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(match self {
            Self::BindPaired { .. } => 200,
            Self::NotifyTest | Self::Diagnostics => 30,
            _ => 15,
        })
    }

    pub fn valid(&self) -> bool {
        match self {
            Self::Snapshot | Self::History | Self::ClearCredential | Self::PairedDevices | Self::SaveSettings { .. }
                | Self::ClearHistory | Self::NotifyTest | Self::Diagnostics => true,
            Self::BindPaired { address, name } => address_format(address)
                && bounded(name, 64) && !name.trim().is_empty()
                && !name.chars().any(|c| c.is_control() || c == '"'),
            Self::SaveCredential { password } => !password.is_empty() && password.len() <= 1024 && !password.contains('\0'),
            Self::RemoveDevice { id } => lower_hex(id, 32),
            Self::SaveDevice { device } => {
                bounded(&device.name, 240) && !device.name.trim().is_empty()
                    && device.adapter == "apple-ble"
                    && device.id.as_ref().is_none_or(|v| lower_hex(v, 32))
                    && device.irk.as_ref().is_none_or(|v| hex(v, 32))
                    && device.irk_blob_path.as_ref().is_none_or(|v| identity_path(v))
                    && !(device.irk.is_some() && device.irk_blob_path.is_some())
                    && (device.id.is_some() || device.irk.is_some() || device.irk_blob_path.is_some())
                    && (-100..=-20).contains(&device.near_rssi)
                    && (-110..=-25).contains(&device.far_rssi)
                    && device.far_rssi < device.near_rssi
                    && device.return_window_seconds.is_none_or(|v| (5..=120).contains(&v))
            }
            Self::SaveNotifications {
                endpoint, device_key, ..
            } => {
                web_url(endpoint)
                    && device_key.as_ref().is_none_or(|v| (8..=256).contains(&v.len())
                        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
            }
        }
    }
}

fn erase(value: &mut String) {
    // Zero bytes preserve UTF-8 validity; volatile writes prevent elision here.
    unsafe {
        for byte in value.as_mut_vec() { std::ptr::write_volatile(byte, 0); }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

impl Drop for DeviceInput {
    fn drop(&mut self) {
        if let Some(value) = self.irk.as_mut() { erase(value); }
        if let Some(value) = self.irk_blob_path.as_mut() { erase(value); }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::SaveCredential { password } => erase(password),
            Self::SaveNotifications { device_key, .. } => {
                if let Some(value) = device_key.as_mut() { erase(value); }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid(value: serde_json::Value) -> bool {
        serde_json::from_value::<Request>(value).is_ok_and(|request| request.valid())
    }

    #[test]
    fn device_request_matches_backend_thresholds_and_identity_sources() {
        let device = json!({"name":"Test device","adapter":"apple-ble","irk":"01".repeat(16),
            "near_rssi":-20,"far_rssi":-25,"enabled":true,"auto_unlock_on_return":false});
        assert!(valid(json!({"op":"save_device","device":device})));
        for (near, far) in [(-101,-110),(-19,-25),(-100,-111),(-20,-24),(-60,-60)] {
            let mut next = device.clone();
            next["near_rssi"] = json!(near);
            next["far_rssi"] = json!(far);
            assert!(!valid(json!({"op":"save_device","device":next})));
        }
        let mut mixed = device;
        mixed["irk_blob_path"] = json!(r"C:\identity.dpapi");
        assert!(!valid(json!({"op":"save_device","device":mixed})));
    }

    #[test]
    fn notification_requests_reject_bad_keys_credentials_in_urls_and_retired_fields() {
        let request = json!({"op":"save_notifications","endpoint":"https://example.invalid/push?tag=watch",
            "enabled":false,"device_key":"test_key-123","notify_on_unlock":true});
        assert!(valid(request.clone()));
        let mut spaced = request.clone();
        spaced["device_key"] = json!("has space");
        assert!(!valid(spaced));
        let mut plain = request.clone();
        plain["endpoint"] = json!("http://192.168.1.10:8080/push");
        assert!(valid(plain));
        for endpoint in ["ftp://example.invalid", "http://user@example.invalid", "https://user@example.invalid", "https://example.invalid/#token", "https://example.invalid/a b"] {
            let mut next = request.clone();
            next["endpoint"] = json!(endpoint);
            assert!(!valid(next));
        }
        // The removed confirmation relay fields are no longer accepted at all.
        let mut retired = request;
        retired["confirmation_url"] = json!("https://example.invalid");
        assert!(!valid(retired));
    }

    #[test]
    fn password_validation_uses_backend_byte_limit_and_disallows_nul() {
        assert!(valid(json!({"op":"save_credential","password":"a".repeat(1024)})));
        for password in ["a".repeat(1025), "密".repeat(342), "invalid\0password".into()] {
            assert!(!valid(json!({"op":"save_credential","password":password})));
        }
    }

    #[test]
    fn settings_request_takes_only_the_lid_switch() {
        assert!(valid(json!({"op":"save_settings","scan_with_lid_closed":true})));
        assert!(!valid(json!({"op":"save_settings"})));
        assert!(!valid(json!({"op":"save_settings","scan_with_lid_closed":"yes"})));
        assert!(!valid(json!({"op":"save_settings","scan_with_lid_closed":true,"extra":1})));
    }
}
