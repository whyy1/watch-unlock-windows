//! One bounded request over private child-process stdin.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use crate::registry::{self, Device, Notifications};

struct Request(Value);
impl Drop for Request {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(text) => crate::enroll::clear_secret(text),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                Value::Object(items) => items.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// A fixed user-facing message that carries no input, so the UI may show it as it is.
#[derive(Debug)]
pub struct Shown(pub &'static str);
impl std::fmt::Display for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}
impl std::error::Error for Shown {}

// Library errors can carry input. Keep the external error stable and redacted; only fixed
// messages, which carry no input, are shown as they are.
fn error_text(error: &anyhow::Error) -> String {
    if let Some(failure) = error.downcast_ref::<crate::notify::Failure>() { return failure.to_string(); }
    if let Some(shown) = error.downcast_ref::<Shown>() { return shown.0.to_owned(); }
    "操作失败，请检查参数、账户密码、配对身份或应用目录权限。".to_owned()
}

/// Operation names are short snake_case words; anything else is not echoed into the history.
fn valid_op(op: &str) -> bool {
    (1..=32).contains(&op.len()) && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// A coarse, input-free description of why an operation failed, for the event history.
fn failure_kind(error: &anyhow::Error) -> String {
    if error.downcast_ref::<Shown>().is_some() || error.downcast_ref::<crate::notify::Failure>().is_some() {
        return "已向用户说明原因".into();
    }
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return format!("文件或系统错误（{:?}）", io.kind());
        }
        if let Some(windows) = cause.downcast_ref::<windows::core::Error>() {
            return format!("Windows 错误 0x{:08X}", windows.code().0);
        }
    }
    "参数或内部检查未通过".into()
}

pub fn run() -> Result<()> {
    let mut op: Option<String> = None;
    let result = (|| -> Result<Value> {
        let mut bytes = Vec::new();
        std::io::stdin().take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 { crate::enroll::clear_bytes(&mut bytes); bail!("Request too large"); }
        let parsed = serde_json::from_slice(&bytes);
        crate::enroll::clear_bytes(&mut bytes);
        let request = Request(parsed.context("Invalid request")?);
        op = request.0.get("op").and_then(Value::as_str).filter(|op| valid_op(op)).map(str::to_owned);
        dispatch(&request.0)
    })();
    let response = match result {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(error) => {
            // The UI only sees a generic sentence; keep which operation failed and the kind of
            // error, never the error text itself, which can carry input or paths.
            if let Some(op) = op.as_deref().filter(|op| !matches!(*op, "snapshot" | "history" | "paired_devices" | "diagnostics")) {
                crate::audit::record("ui_request_failed", None, &format!("操作 {op} 未完成：{}", failure_kind(&error)));
            }
            json!({"ok":false,"error":error_text(&error)})
        }
    };
    println!("{}", serde_json::to_string(&response)?);
    std::io::stdout().flush()?;
    Ok(())
}

fn text<'a>(request: &'a Value, key: &str) -> Result<&'a str> {
    request.get(key).and_then(Value::as_str).context("Missing text field")
}

fn secret_configured(name: &str) -> bool {
    let result = registry::data_dir().and_then(|dir| crate::vault::load_secret(&dir, name));
    match result {
        Ok(mut clear) => { let valid = !clear.is_empty(); crate::enroll::clear_bytes(&mut clear); valid }
        Err(_) => false,
    }
}

pub fn snapshot() -> Result<Value> {
    let devices = registry::load_devices()?.iter().map(|device| {
        let mut value = serde_json::to_value(device).unwrap_or_default();
        value["identity_configured"] = json!(registry::identity_configured(&device.id));
        value["wearer_state"] = json!("unknown");
        value
    }).collect::<Vec<_>>();
    let config = registry::load_notifications()?;
    let status = registry::data_dir()?.join("status.json");
    let status: Value = registry::read_json(&status).unwrap_or(json!({"running":false}));
    let fresh = status.get("at_ms").and_then(Value::as_u64)
        .is_some_and(|at| crate::audit::epoch_ms().checked_sub(at).is_some_and(|age| age < 5000));
    Ok(json!({
        "devices":devices,
        "notifications":{
            "endpoint":config.endpoint,"enabled":config.enabled,
            "configured":secret_configured("bark-key.dpapi"),
            "notify_on_unlock":config.notify_on_unlock
        },
        "settings":registry::load_settings().unwrap_or_default(),
        "credential_configured":crate::enroll::credential_configured(),
        "backend_running":fresh && status["running"] == true,
        "runtime":if fresh { status } else { json!({"running":false}) },
        "history":crate::audit::history()?
    }))
}

fn dispatch(request: &Value) -> Result<Value> {
    match text(request,"op")? {
        "snapshot" => snapshot(),
        "history" => Ok(serde_json::to_value(crate::audit::history()?)?),
        "diagnostics" => crate::diagnostics::report(),
        "clear_history" => {
            crate::audit::clear()?;
            snapshot()
        }
        "notify_test" => {
            crate::notify::notify_test()?;
            crate::audit::record("notification_test",None,"已发送测试通知；不授予解锁权限");
            snapshot()
        }
        "save_device" => save_device(request.get("device").context("Missing device")?),
        "remove_device" => remove_device(text(request,"id")?),
        "paired_devices" => crate::paired::snapshot(),
        "bind_paired" => {
            crate::bind::launch(text(request,"address")?, text(request,"name")?)?;
            snapshot()
        }
        "save_notifications" => save_notifications(request),
        "save_settings" => {
            let scan_with_lid_closed = request.get("scan_with_lid_closed").and_then(Value::as_bool)
                .context("Missing scan_with_lid_closed flag")?;
            registry::write_json("settings.json", &registry::Settings { scan_with_lid_closed })?;
            crate::audit::record("settings_saved",None,if scan_with_lid_closed {"已开启合盖时继续检测手表"} else {"已关闭合盖时继续检测手表"});
            snapshot()
        }
        "save_credential" => {
            if !registry::load_devices()?.iter().any(|d| registry::identity_configured(&d.id)) {
                bail!("Bind an identity before storing credentials");
            }
            let password = text(request,"password")?;
            if password.is_empty() || password.len() > 1024 || password.contains('\0') { bail!("Invalid password"); }
            crate::enroll::enroll_password(password)?;
            crate::audit::record("credential_saved",None,"当前 Windows 账户凭据已验证并加密保存");
            snapshot()
        }
        "clear_credential" => {
            crate::enroll::clear_credential()?;
            crate::audit::record("credential_removed",None,"Windows 解锁凭据已移除");
            snapshot()
        }
        _ => bail!("Unsupported operation"),
    }
}

fn save_device(input: &Value) -> Result<Value> {
    let devices = registry::load_devices()?;
    let provided = input.get("id").and_then(Value::as_str).filter(|id| !id.is_empty());
    if provided.is_none() && devices.len() >= 16 { bail!("Too many devices"); }
    let id = match provided {
        Some(id) if devices.iter().any(|d| d.id == id) => id.to_owned(),
        Some(_) => bail!("Unknown device"),
        None => registry::random_hex(16)?,
    };
    let number = |key| -> Result<i16> {
        input.get(key).and_then(Value::as_i64).and_then(|v| i16::try_from(v).ok()).context("Invalid threshold")
    };
    let boolean = |key| -> Result<bool> { input.get(key).and_then(Value::as_bool).context("Invalid flag") };
    // Address is set only by the elevated binding flow; ordinary saves keep the existing binding.
    let existing = devices.iter().find(|d| d.id == id);
    let address = existing.and_then(|d| d.address.clone());
    // Optional for older UIs: keep the stored value, or the default for a new device.
    let return_window_seconds = match input.get("return_window_seconds") {
        Some(value) => value.as_u64().and_then(|v| u16::try_from(v).ok()).context("Invalid return window")?,
        None => existing.map_or_else(registry::default_return_window, |d| d.return_window_seconds),
    };
    let device = Device { id: id.clone(), name: text(input,"name")?.trim().into(),
        adapter: text(input,"adapter")?.into(), near_rssi:number("near_rssi")?, far_rssi:number("far_rssi")?,
        auto_unlock_on_return:boolean("auto_unlock_on_return")?, enabled:boolean("enabled")?, address,
        return_window_seconds };
    device.validate()?;
    let key = input.get("irk").and_then(Value::as_str).filter(|value| !value.is_empty());
    let blob = input.get("irk_blob_path").and_then(Value::as_str).filter(|value| !value.is_empty());
    if key.is_some() && blob.is_some() { bail!("Choose one identity source"); }
    if key.is_some() || blob.is_some() {
        let mut identity = if let Some(path) = blob {
            registry::import_identity(std::path::Path::new(path))?
        } else { crate::irk::parse_irk_hex(key.unwrap())? };
        let result = crate::vault::save_secret(&registry::data_dir()?, &format!("device-{id}.dpapi"), &identity);
        crate::vault::erase(&mut identity);
        result?;
    } else if !registry::identity_configured(&id) { bail!("Missing device identity"); }
    let next = if devices.iter().any(|current| current.id == id) {
        devices.into_iter().map(|current| if current.id == id { device.clone() } else { current }).collect::<Vec<_>>()
    } else { devices.into_iter().chain(Some(device)).collect::<Vec<_>>() };
    registry::save_devices(&next)?;
    crate::audit::record("device_saved",Some(&id),"设备身份与距离策略已保存");
    snapshot()
}

pub fn import_device(path: &std::path::Path,name: &str) -> Result<()> {
    let input = json!({"name":name,"adapter":"apple-ble","irk_blob_path":path.to_str().context("Invalid file path")?,
        "near_rssi":-60,"far_rssi":-75,"auto_unlock_on_return":true,"enabled":true});
    save_device(&input)?;
    println!("Encrypted identity imported. Verify the matched signal in the application before enabling unlock.");
    Ok(())
}

fn remove_device(id: &str) -> Result<Value> {
    if !registry::valid_id(id) { bail!("Invalid device ID"); }
    let devices = registry::load_devices()?;
    if !devices.iter().any(|device| device.id == id) { bail!("Unknown device"); }
    registry::save_devices(&devices.into_iter().filter(|d| d.id != id).collect::<Vec<_>>())?;
    crate::vault::delete_secret(&registry::data_dir()?, &format!("device-{id}.dpapi"))?;
    crate::audit::record("device_removed",Some(id),"设备已解绑");
    snapshot()
}

fn validated_notifications(request: &Value) -> Result<(Notifications, Option<&str>)> {
    let endpoint = text(request,"endpoint")?;
    crate::notify::validate_url(endpoint)?;
    let enabled = request.get("enabled").and_then(Value::as_bool).context("Missing enabled flag")?;
    let key = request.get("device_key").and_then(Value::as_str).filter(|key| !key.is_empty());
    if let Some(key) = key {
        if !(8..=256).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            bail!("Invalid Bark key");
        }
    }
    // Optional for older UIs: keep the stored choice when the field is absent.
    let notify_on_unlock = match request.get("notify_on_unlock") {
        Some(value) => value.as_bool().context("Invalid notify_on_unlock flag")?,
        None => registry::load_notifications().map(|current| current.notify_on_unlock).unwrap_or(true),
    };
    Ok((Notifications { endpoint:endpoint.into(), enabled, notify_on_unlock }, key))
}

fn save_notifications(request: &Value) -> Result<Value> {
    // Validate every field before changing any encrypted file.
    let (config, key) = validated_notifications(request)?;
    let dir = registry::data_dir()?;
    if let Some(key) = key { crate::vault::save_secret(&dir,"bark-key.dpapi",key.as_bytes())?; }
    registry::write_json("notifications.json", &config)?;
    crate::audit::record("notifications_saved",None,"通知配置已保存，秘密保持加密");
    snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_records_name_the_operation_and_kind_only() {
        assert!(valid_op("save_settings"));
        for op in ["", "Save", "save settings", "../x", &"a".repeat(33)] { assert!(!valid_op(op)); }
        let io = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied)).context(r"C:\Users\someone");
        assert_eq!(failure_kind(&io), "文件或系统错误（PermissionDenied）");
        assert_eq!(failure_kind(&anyhow::anyhow!("secret input")), "参数或内部检查未通过");
        assert_eq!(failure_kind(&anyhow::Error::new(Shown("密码不对"))), "已向用户说明原因");
    }

    #[test]
    fn only_fixed_messages_reach_the_ui() {
        assert!(error_text(&anyhow::Error::new(Shown("密码不对"))).starts_with("密码不对"));
        let wrapped = anyhow::Error::new(Shown("密码不对")).context("Save credential");
        assert!(error_text(&wrapped).starts_with("密码不对"));
        assert!(error_text(&anyhow::anyhow!("secret input")).starts_with("操作失败"));
    }

    #[test]
    fn notification_validation_finishes_before_storage() {
        let valid = json!({"endpoint":"https://api.day.app/push", "enabled":false,
            "device_key":"example-key", "notify_on_unlock":false});
        let (config, key) = validated_notifications(&valid).unwrap();
        assert!(!config.notify_on_unlock);
        assert_eq!(key, Some("example-key"));
        for invalid in [json!({"enabled":"false"}), json!({"device_key":"has space"}),
            json!({"endpoint":"ftp://api.day.app/push"}), json!({"notify_on_unlock":"yes"})] {
            let mut request = valid.clone();
            for (key, value) in invalid.as_object().unwrap() { request[key] = value.clone(); }
            assert!(validated_notifications(&request).is_err());
        }
    }
}
