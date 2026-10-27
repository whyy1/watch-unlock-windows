//! Bounded event history; no credentials or raw BLE addresses.

use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub event: String,
    pub device_id: Option<String>,
    pub detail: String,
}

pub fn record(event: &str, device_id: Option<&str>, detail: &str) {
    // Callsites supply fixed text, or fixed text with our own numbers; never external errors.
    let _ = append(Event { at_ms: epoch_ms(), event: event.into(),
        device_id: device_id.map(str::to_owned), detail: detail.into() });
}

pub fn epoch_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn append(event: Event) -> anyhow::Result<()> {
    let dir = crate::registry::data_dir()?;
    crate::vault::ensure_private_dir(&dir)?;
    let path = dir.join("events.jsonl");
    if path.exists() { crate::vault::ensure_private_file(&path)?; }
    if path.metadata().is_ok_and(|m| m.len() > 1024 * 1024) {
        let previous = dir.join("events.previous.jsonl");
        if previous.exists() {
            crate::vault::ensure_private_file(&previous)?;
            std::fs::remove_file(&previous)?;
        }
        std::fs::rename(&path, previous)?;
    }
    let mut json = serde_json::to_vec(&event)?;
    json.push(b'\n');
    std::fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(&json)?;
    Ok(())
}

/// Removes the current and rotated history, then records that it was cleared so the
/// gap stays visible.
pub fn clear() -> anyhow::Result<()> {
    let dir = crate::registry::data_dir()?;
    for name in ["events.jsonl", "events.previous.jsonl"] {
        let path = dir.join(name);
        if path.exists() {
            crate::vault::ensure_private_file(&path)?;
            std::fs::remove_file(&path)?;
        }
    }
    record("history_cleared", None, "解锁记录已清空");
    Ok(())
}

pub fn history() -> anyhow::Result<Vec<Event>> {
    recent(200)
}

/// The newest `limit` events, newest first.
pub fn recent(limit: usize) -> anyhow::Result<Vec<Event>> {
    let path = crate::registry::data_dir()?.join("events.jsonl");
    if !path.exists() { return Ok(Vec::new()); }
    crate::vault::ensure_private_file(&path)?;
    let bytes = crate::vault::read_limited_file(&path, 2 * 1024 * 1024)?;
    let events = std::str::from_utf8(&bytes)?.lines()
        .filter_map(|line| serde_json::from_str(&line).ok()).collect::<Vec<Event>>();
    Ok(events.into_iter().rev().take(limit).collect())
}
