//! Minimizing hides the window to the notification area. The background never depends on this
//! window, so the notice after hiding says whether it is running and that the window can close.

use serde_json::json;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewWindow};
use tauri_plugin_notification::NotificationExt;

const TITLE: &str = "Watch Unlock 已缩小到托盘";

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "打开 Watch Unlock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Watch Unlock")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show(app),
            "quit" => crate::quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() { tray = tray.icon(icon.clone()); }
    tray.build(app)?;
    Ok(())
}

pub fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Called on every resize; acts only when the window has just been minimized.
pub fn hide_if_minimized(window: &WebviewWindow) {
    if !window.is_minimized().unwrap_or(false) || !window.is_visible().unwrap_or(false) { return; }
    hide(window);
}

/// The 缩小到托盘 button in the top bar: the same as minimizing.
#[tauri::command]
pub fn hide_to_tray(window: WebviewWindow) {
    hide(&window);
}

fn hide(window: &WebviewWindow) {
    let _ = window.hide();
    let app = window.app_handle().clone();
    std::thread::spawn(move || {
        let _ = app.notification().builder().title(TITLE).body(notice(background_running())).show();
    });
}

/// None when the background could not be asked.
fn background_running() -> Option<bool> {
    let response = crate::backend::request(json!({"op": "snapshot"})).ok()?;
    response.get("data")?.get("backend_running")?.as_bool()
}

fn notice(running: Option<bool>) -> &'static str {
    match running {
        Some(true) => "后台正在运行，锁屏后走开再回来即可解锁。后台不依赖这个窗口，不用时可以直接关掉窗口。",
        Some(false) => "后台没有运行，锁屏后不会自动解锁。点托盘图标打开窗口，再点「启动后台」。",
        None => "读不到后台状态。点托盘图标打开窗口查看。",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_names_the_background_state() {
        assert!(notice(Some(true)).contains("正在运行"));
        assert!(notice(Some(true)).contains("关掉窗口"));
        assert!(notice(Some(false)).contains("启动后台"));
        assert!(notice(None).contains("读不到"));
    }
}
