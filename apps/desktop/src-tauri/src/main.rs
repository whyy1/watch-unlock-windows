#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;
mod diagnostics;
mod links;
mod pairing;
mod processes;
mod request;
mod setup;
mod tray;

use processes::{Processes, RuntimeStatus};
use serde_json::Value;
use tauri::{AppHandle, Manager, State, WindowEvent};

#[tauri::command]
async fn backend_request(request: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || backend::request(request))
        .await
        .map_err(|_| "backend_task_failed")?
}

#[tauri::command]
fn runtime_status(processes: State<Processes>) -> Result<RuntimeStatus, String> {
    processes::status(&processes)
}

#[tauri::command]
fn start_daemon(processes: State<Processes>) -> Result<RuntimeStatus, String> {
    processes::start_daemon(&processes)
}

#[tauri::command]
fn stop_daemon(processes: State<Processes>) -> Result<RuntimeStatus, String> {
    processes::stop_daemon(&processes)
}

#[tauri::command]
fn start_scan(app: AppHandle, processes: State<Processes>) -> Result<(), String> {
    processes::start_scan(app, &processes)
}

#[tauri::command]
fn stop_scan(processes: State<Processes>) -> Result<(), String> {
    processes::stop_scan(&processes)
}

#[tauri::command]
fn start_pairing(app: AppHandle, processes: State<Processes>) -> Result<(), String> {
    pairing::start(app, &processes)
}

#[tauri::command]
fn stop_pairing(processes: State<Processes>) -> Result<(), String> {
    pairing::stop(&processes)
}

/// Stops the scan and pairing helpers this window started; the background keeps running.
fn stop_window_tasks(app: &AppHandle) {
    let state = app.state::<Processes>();
    let _ = processes::stop_scan(&state);
    let _ = pairing::stop(&state);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        let scanning = state.scan.lock().map(|slot| slot.is_some()).unwrap_or(false);
        let pairing = state.pairing.lock().map(|slot| slot.is_some()).unwrap_or(false);
        if !scanning && !pairing { break; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The tray's 退出: the same cleanup as closing the window.
pub fn quit(app: &AppHandle) {
    stop_window_tasks(app);
    app.exit(0);
}

fn main() {
    tauri::Builder::default()
        // A second launch, for example from the Start menu while hidden in the tray, shows this window.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| tray::show(app)))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .manage(Processes::default())
        .setup(|app| {
            tray::install(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { .. } => stop_window_tasks(window.app_handle()),
            WindowEvent::Resized(_) => {
                if let Some(window) = window.app_handle().get_webview_window(window.label()) {
                    tray::hide_if_minimized(&window);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            backend_request, runtime_status, start_daemon, stop_daemon, start_scan, stop_scan,
            start_pairing, stop_pairing
            , links::open_link, tray::hide_to_tray, setup::setup_status, setup::set_autostart, diagnostics::export_diagnostics,
            diagnostics::diagnostics_summary
        ])
        .run(tauri::generate_context!())
        .expect("Unable to launch Watch Unlock desktop");
}
