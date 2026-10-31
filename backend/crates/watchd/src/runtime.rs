//! Device-independent policy and Windows side effects.

use anyhow::Result;
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{mpsc,Arc};
use std::sync::atomic::{AtomicU64,Ordering};
use std::time::{Duration,Instant,SystemTime};
use watch_unlock_domain::{Decision,Session};
use windows::core::PCWSTR;
use windows::Devices::Bluetooth::BluetoothError;
use windows::Win32::Foundation::{CloseHandle,GetLastError,ERROR_ALREADY_EXISTS};
use windows::Win32::System::Com::{CoInitializeEx,COINIT_MULTITHREADED};
use windows::Win32::System::Power::{SetThreadExecutionState,ES_CONTINUOUS,ES_DISPLAY_REQUIRED};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{CreateMutexW,GetCurrentProcessId};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo,LASTINPUTINFO};
use crate::{adapters,audit,ble,pipe,registry,session};

#[path = "runtime_policy.rs"]
mod policy;
use policy::{accepts_signal, input_after, lid_close_stops_scanning, lid_switch_change, lock_cause, DeviceAuthority, SubmissionConditions, SubmissionGate};

struct DeviceRuntime {
    config:registry::Device,
    adapter:Box<dyn adapters::DeviceAdapter>,
    authority:DeviceAuthority,
    /// Tick of this lock cycle's far-then-near return. With seamless unlock off, only
    /// keyboard or mouse input after it may submit.
    return_tick:Option<u32>,
}

fn devices(previous:&[DeviceRuntime])->Result<Vec<DeviceRuntime>> {
    registry::load_devices()?.into_iter().filter(|d|d.enabled).map(|config| {
        let authority=previous.iter().find(|device|device.config.id==config.id)
            .map_or_else(||DeviceAuthority::new(config.policy()),|device|device.authority.with_policy(config.policy()))
            .with_return_window(config.return_window())
            .with_hold_while_near(!config.auto_unlock_on_return);
        let return_tick=previous.iter().find(|device|device.config.id==config.id).and_then(|device|device.return_tick);
        Ok(DeviceRuntime {adapter:adapters::create(&config)?,authority,config,return_tick})
    }).collect()
}

fn revision()->Vec<(String,Option<(SystemTime,u64)>)> {
    let dir=registry::data_dir().ok();
    let names=["devices.json","notifications.json","settings.json","cred.blob","bark-key.dpapi"]
        .into_iter().map(String::from)
        .chain(registry::load_devices().unwrap_or_default().into_iter()
            .map(|device|format!("device-{}.dpapi",device.id))).collect::<BTreeSet<_>>();
    names.into_iter().map(|name| {
        let metadata=dir.as_ref().and_then(|dir|std::fs::metadata(dir.join(&name)).ok());
        let stamp=metadata.and_then(|value|Some((value.modified().ok()?,value.len())));
        (name,stamp)
    }).collect()
}

/// Tick of the last keyboard or mouse input in this session (GetLastInputInfo is session-wide).
fn last_input_tick()->Option<u32> {
    let mut info=LASTINPUTINFO{cbSize:std::mem::size_of::<LASTINPUTINFO>() as u32,dwTime:0};
    unsafe {GetLastInputInfo(&mut info)}.as_bool().then_some(info.dwTime)
}

/// How long a submitted unlock keeps the display on; a switched-off monitor takes a few seconds to light up.
const DISPLAY_HOLD:Duration=Duration::from_secs(8);

/// History line for a scanner Windows stopped, naming its reason when it gave one.
fn scanner_stopped_detail(error:BluetoothError)->String {
    if error==BluetoothError::Success {return "扫描器已停止，旧距离证据已立即撤销".into();}
    format!("扫描器已停止（Windows 报告：{}），旧距离证据已立即撤销",ble::error_label(error))
}

fn watcher(sender:&mpsc::SyncSender<ble::Advertisement>,counter:&Arc<AtomicU64>)->Result<ble::AdvertisementWatcher> {
    let output=sender.clone();let count=Arc::clone(counter);
    let watcher=ble::make_watcher(move |adv| {
        count.fetch_add(1,Ordering::Relaxed);
        let _=output.try_send(adv.clone());
    })?;
    watcher.start()?;
    Ok(watcher)
}

pub fn run()->Result<()> {
    let mut session_id=0;
    unsafe {ProcessIdToSessionId(GetCurrentProcessId(),&mut session_id)?;}
    let mutex_name=format!("Local\\WatchUnlockWindowsDaemon-{session_id}\0").encode_utf16().collect::<Vec<_>>();
    let mutex=unsafe {CreateMutexW(None,true,PCWSTR(mutex_name.as_ptr()))?};
    if unsafe {GetLastError()}==ERROR_ALREADY_EXISTS {unsafe {let _=CloseHandle(mutex);} anyhow::bail!("Already running");}
    // The process owns this mutex until exit; the OS closes it on termination.
    let _mutex=mutex;
    // Do not reset: a stop requested while this process starts must still be honoured.
    let stop=crate::stop::StopSignal::open(false)?;
    if registry::remove_legacy_confirmation().is_err() {
        audit::record("legacy_cleanup_failed",None,"旧版手表确认功能的残留数据未能清理");
    }
    unsafe {let _=CoInitializeEx(None,COINIT_MULTITHREADED);}
    let (session_tx,session_rx)=mpsc::channel();
    let (adv_tx,adv_rx)=mpsc::sync_channel(64);
    let (pipe_tx,pipe_rx)=mpsc::channel();
    let (command_tx,command_rx)=mpsc::channel();
    session::start_session_events(session_tx)?;
    pipe::start_pipe_server(pipe_tx,command_rx)?;
    let counter=Arc::new(AtomicU64::new(0));
    let mut scanner=Some(watcher(&adv_tx,&counter)?);
    let mut active=devices(&[])?;
    let origin=Instant::now();
    let mut lock=Session{generation:1,locked:session::current_session_locked().unwrap_or(false)};
    let mut submissions=SubmissionGate::default();
    let mut provider=None;
    let mut scan_requested=true;
    let mut previous_revision=revision();
    let mut last_housekeeping=Instant::now();
    let mut last_rebuild=Instant::now();
    let mut evidence_floor=Instant::now();
    let mut deferred_session=None;
    let mut session_known=true;
    // Set when this lock cycle submitted an unlock, for the post-unlock notification.
    let mut notify_on_unlock=false;
    // Only for guessing why the session locked.
    let mut display_off_at:Option<Instant>=None;
    let mut settings=registry::load_settings().unwrap_or_default();
    // Lid state as last reported; scanning stops while it is closed unless the user opted in.
    let mut lid_closed=false;
    // Why an authorized return is not being submitted: (reasons, since, recorded).
    let mut blocked:Option<(String,Instant,bool)>=None;
    // Until when this thread holds ES_DISPLAY_REQUIRED after submitting an unlock.
    let mut display_hold_until:Option<Instant>=None;
    audit::record("backend_started",None,"后台已启动；佩戴与手表锁定状态未知");
    loop {
        if display_hold_until.is_some_and(|until|Instant::now()>=until) {
            unsafe {SetThreadExecutionState(ES_CONTINUOUS);}
            display_hold_until=None;
        }
        if stop.requested() {
            if display_hold_until.take().is_some() {unsafe {SetThreadExecutionState(ES_CONTINUOUS);}}
            audit::record("backend_stopped",None,"后台已按请求停止，不再参与解锁");
            let _=registry::write_json("status.json",&json!({"running":false,"at_ms":audit::epoch_ms()}));
            return Ok(());
        }
        let now=Instant::now();
        let at_ms=origin.elapsed().as_millis() as u64;
        let mut invalidate=false;
        let mut new_lock=false;
        // Any invalidation in this tick other than the lock itself voids pre-lock evidence.
        let mut revoked=false;
        let mut write_status=false;
        loop {
            let event=match deferred_session.take().map(Ok).unwrap_or_else(||session_rx.try_recv()) {
                Ok(event)=>event,
                Err(mpsc::TryRecvError::Empty)=>break,
                Err(mpsc::TryRecvError::Disconnected)=>anyhow::bail!("Session monitoring unavailable"),
            };
            match event {
                session::SessionEvent::Lock if !lock.locked=>{
                    lock=Session{generation:lock.generation+1,locked:true};
                    session_known=true;
                    submissions=SubmissionGate::default();invalidate=true;new_lock=true;notify_on_unlock=false;
                }
                session::SessionEvent::Unlock=>{
                    if lock.locked && std::mem::take(&mut notify_on_unlock) {crate::notify::notify_unlock_async();}
                    lock.locked=false;session_known=true;invalidate=true;provider=None;
                    // A WTS event cannot prove which credential provider succeeded.
                    audit::record("session_unlocked",None,"Windows 会话已解锁；认证来源未归因");
                }
                session::SessionEvent::Pause(session::PauseReason::DisplayOff)=>{display_off_at=Some(Instant::now());},
                session::SessionEvent::Pause(session::PauseReason::LidClosed)=>{
                    lid_closed=true;
                    if lid_close_stops_scanning(settings.scan_with_lid_closed) {
                        scan_requested=false;scanner=None;invalidate=true;revoked=true;
                    } else {
                        audit::record("lid_closed_scanning",None,"已合盖，按设置继续检测手表");
                    }
                }
                session::SessionEvent::Pause(_)=>{
                    scan_requested=false;scanner=None;invalidate=true;revoked=true;
                }
                session::SessionEvent::Resume=>{scan_requested=true;invalidate=true;revoked=true;}
                session::SessionEvent::Wake(reason)=>{
                    if reason==session::WakeReason::LidOpen {lid_closed=false;}
                    scan_requested=true;
                    // Display wake never creates authority. A healthy running scanner
                    // retains previously observed far evidence across display-off.
                    if scanner.is_none(){invalidate=true;revoked=true;}
                }
                _=>{}
            }
        }
        while let Ok(event)=pipe_rx.try_recv() {
            match event {
                pipe::PipeEvent::Hello(connection)=>{
                    // Once per connection: shows when the logon UI actually became ready.
                    if provider.is_none() {
                        audit::record("provider_connected",None,if lock.locked {"登录界面组件已连接，可以接收解锁"}
                            else {"登录界面组件已连接（此时还没收到锁屏通知）"});
                    }
                    provider=Some(connection)
                }
                pipe::PipeEvent::Gone=>{
                    // After a delivered unlock this is the normal end of the logon screen.
                    if provider.is_some() && lock.locked && !submissions.submitted() {
                        audit::record("provider_disconnected",None,"登录界面组件已断开，重新连接前无法解锁");
                    }
                    provider=None;
                }
            }
        }
        // Revoke as soon as a stopped adapter is observed, independently of the
        // slower rebuild backoff. No queued packet can revive a failed scanner.
        if let Some(stopped)=scanner.as_ref().filter(|scanner|!scanner.is_running()) {
            let detail=scanner_stopped_detail(stopped.stop_error());
            scanner=None;invalidate=true;revoked=true;
            audit::record("scanner_unavailable",None,&detail);
        }
        if last_housekeeping.elapsed()>=Duration::from_secs(1) {
            last_housekeeping=now;
            write_status=true;
            let observed=session::current_session_locked();
            session_known=observed.is_ok();
            match observed {
                Ok(locked) if locked!=lock.locked=>{
                    if !locked && std::mem::take(&mut notify_on_unlock) {crate::notify::notify_unlock_async();}
                    lock=Session{generation:lock.generation+1,locked};
                    if locked {submissions=SubmissionGate::default();new_lock=true;notify_on_unlock=false;}
                    invalidate=true;
                    audit::record("session_reconciled",None,"会话状态已重新核对，旧授权已撤销");
                }
                Err(_)=>{invalidate=true;revoked=true;},
                _=>{}
            }
            let next_revision=revision();
            if next_revision!=previous_revision {
                active=devices(&active)?;previous_revision=next_revision;invalidate=true;revoked=true;
                let next_settings=registry::load_settings().unwrap_or_default();
                // A switch flipped while the lid is shut applies at once.
                if let Some(scan)=lid_switch_change(lid_closed,settings.scan_with_lid_closed,next_settings.scan_with_lid_closed) {
                    scan_requested=scan;
                    if !scan {scanner=None;}
                }
                settings=next_settings;
                lock.generation+=1;
                audit::record("configuration_reloaded",None,"配置变更，旧授权已撤销");
            }
            if scan_requested && scanner.as_ref().is_none_or(|scanner|!scanner.is_running())
                && last_rebuild.elapsed()>Duration::from_secs(5) {
                drop(scanner.take());invalidate=true;revoked=true;last_rebuild=now;
                scanner=watcher(&adv_tx,&counter).ok();
                audit::record("scanner_reset",None,if scanner.is_some() {"扫描器已重建，旧距离证据已撤销"}
                    else {"扫描器重建失败，5 秒后重试"});
            }
        }
        if invalidate {
            if new_lock {blocked=None;}
            let lock_now=Instant::now();
            // Dynamic Lock only locks once the watch is already out of range, so no far signal
            // follows the lock. A far crossing seen just before it, on a scanner that stayed
            // healthy up to the lock, counts for this lock cycle.
            let trusted=new_lock && lock.locked && !revoked && session_known && scan_requested
                && scanner.as_ref().is_some_and(|scanner|scanner.is_running());
            let before=active.iter().map(|device|(device.authority.departed(),device.authority.last_signal())).collect::<Vec<_>>();
            evidence_floor=lock_now;
            let _=command_tx.send(pipe::PipeCommand::Cancel);
            for device in &mut active {
                device.authority=device.authority.invalidate(lock,at_ms)?;
                if new_lock {device.return_tick=None;}
            }
            if new_lock && lock.locked {
                let idle=last_input_tick().map(|last|Duration::from_millis(unsafe {GetTickCount()}.wrapping_sub(last) as u64));
                let cause=lock_cause(idle,display_off_at.map(|at|lock_now.saturating_duration_since(at)),session::dynamic_lock_enabled());
                let idle_text=idle.map_or_else(String::new,|idle|format!("；锁屏前已无操作 {} 秒",idle.as_secs()));
                audit::record("session_locked",None,&format!("新锁屏周期（推测：{}{idle_text}）",cause.text()));
                for (device,(departed,last)) in active.iter_mut().zip(before) {
                    let seen=last.map(|(at,rssi)|format!("最后信号 {rssi} dBm，在 {} 秒前",lock_now.saturating_duration_since(at).as_secs()));
                    let id=Some(device.config.id.as_str());
                    match seen {
                        Some(seen) if departed && trusted=>{
                            device.authority=device.authority.arm_departed();
                            audit::record("far_before_lock",id,&format!("锁屏前手表已越过远离阈值（{seen}），回来即可解锁"));
                        }
                        Some(seen) if departed=>audit::record("lock_watch_state",id,
                            &format!("锁屏前手表已越过远离阈值（{seen}），但扫描器或配置同时有变化，这次不算；要走远后再回来")),
                        Some(seen)=>audit::record("lock_watch_state",id,
                            &format!("锁屏时手表未越过远离阈值（{seen}）；要走远后再回来")),
                        None=>audit::record("lock_watch_state",id,"锁屏前没有收到这块手表的信号；要走远后再回来"),
                    }
                }
            }
            for _ in adv_rx.try_iter().take(64) {}
        }
        // Bound each batch so BLE traffic cannot starve power/session revocation.
        for adv in adv_rx.try_iter().take(64) {
            let sample_now=Instant::now();
            if !accepts_signal(adv.received_at,sample_now,evidence_floor,
                session_known && scan_requested && scanner.as_ref().is_some_and(|scanner|scanner.is_running())) {continue;}
            if !(-127..=20).contains(&adv.rssi) {continue;}
            for device in &mut active {
                if !device.adapter.matches(&adv){continue;}
                let transition=device.authority.observe(lock,adv.rssi,adv.received_at,at_ms)?;
                device.authority=transition.authority;
                if transition.crossed_far {
                    audit::record("far_threshold_crossed",Some(&device.config.id),"已观察到远阈值越界，无驻留等待");
                }
                if transition.decision==Decision::ReturnUnlock {
                    device.return_tick=Some(unsafe {GetTickCount()});
                    audit::record("return_detected",Some(&device.config.id),if device.config.auto_unlock_on_return {
                        "已观察到远离后的首次近阈值返回"
                    } else {"已观察到远离后返回；无感解锁已关闭，等待键盘或鼠标操作"});
                }
            }
        }
        for device in &mut active {
            let (authority,expired)=device.authority.expire_return(Instant::now());
            device.authority=authority;
            if expired {
                device.return_tick=None;
                audit::record("return_authorization_expired",Some(&device.config.id),"返回授权已过期，需要新的远离证据");
            }
        }
        let now=Instant::now();
        let last_input=last_input_tick();
        let authorized=active.iter().find(|device| device.authority.authorized(now)
            && (device.config.auto_unlock_on_return || device.return_tick.is_some_and(|tick|input_after(last_input,tick))));
        if let Some(device)=authorized {
            let verified_locked=session::current_session_locked().unwrap_or(false);
            let credential_configured=crate::enroll::credential_configured();
            // OS/storage checks may block. Re-evaluate absolute signal deadlines
            // afterwards, and handle any intervening session event before the
            // next attempt instead of dropping it from the queue.
            let session_event_pending=match session_rx.try_recv() {
                Ok(event)=>{deferred_session=Some(event);true},
                Err(mpsc::TryRecvError::Empty)=>false,
                Err(mpsc::TryRecvError::Disconnected)=>anyhow::bail!("Session monitoring unavailable"),
            };
            let configuration_current=revision()==previous_revision;
            if !configuration_current {
                last_housekeeping=Instant::now()-Duration::from_secs(1);
            }
            let deadline=device.authority.authorization_deadline(Instant::now());
            let conditions=SubmissionConditions {locked:lock.locked,provider_ready:provider.is_some(),
                verified_locked:verified_locked && session_known && !session_event_pending && configuration_current,credential_configured,
                scanner_running:scan_requested && scanner.as_ref().is_some_and(|scanner|scanner.is_running())};
            let (next,submit)=submissions.reserve(conditions,deadline.is_some());
            submissions=next;
            // Record a block that lasts, not the brief ones while a session event or reload settles.
            if submit || submissions.submitted() || deadline.is_none() {blocked=None;}
            else {
                let why=conditions.blockers().join("、");
                match &mut blocked {
                    Some((reasons,since,recorded)) if *reasons==why=>if !*recorded && since.elapsed()>=Duration::from_secs(1) {
                        *recorded=true;
                        audit::record("unlock_blocked",Some(&device.config.id),&format!("可以解锁，但暂未提交：{why}"));
                    },
                    _=>blocked=Some((why,Instant::now(),false)),
                }
            }
            if submit {
                // Mark before IPC: any outcome consumes this lock cycle's attempt.
                let device_id=device.config.id.clone();
                for device in &mut active {device.authority=device.authority.consume_submission();device.return_tick=None;}
                if let (Some(connection),Some(valid_until))=(provider.clone(),deadline) {
                    let _=command_tx.send(pipe::PipeCommand::Unlock(pipe::UnlockGrant::new(connection,valid_until)));
                }
                notify_on_unlock=true;
                audit::record("unlock_submitted",Some(&device_id),"已向验证过的 Credential Provider 提交一次请求");
                // Held for a few seconds, then released in the loop so the power plan applies again.
                unsafe {SetThreadExecutionState(ES_CONTINUOUS|ES_DISPLAY_REQUIRED);}
                display_hold_until=Some(Instant::now()+DISPLAY_HOLD);
            }
        }
        if write_status {
            let status_now=Instant::now();
            let status=active.iter().map(|device| {
                // The last signal however old, so the UI can tell a slow watch from a silent one.
                let last=device.authority.last_signal();
                json!({"id":device.config.id,
                "rssi":device.authority.rssi(status_now),
                "last_rssi":last.map(|(_,rssi)|rssi),
                "last_seen_ms":last.map(|(at,_)|status_now.saturating_duration_since(at).as_millis() as u64),
                "presence":if device.authority.near(status_now){"near"}else if device.authority.armed(){"away"}else{"unknown"},
                "armed":device.authority.armed(),"wearer_state":"unknown"})}).collect::<Vec<_>>();
            let _=registry::write_json("status.json",&json!({"running":true,"at_ms":audit::epoch_ms(),
                "locked":lock.locked,"provider_ready":provider.is_some(),"scanner_active":scanner.as_ref().is_some_and(|s|s.is_running()),
                "submitted_this_lock":submissions.submitted(),"devices":status}));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_stop_names_the_windows_reason_only_when_given() {
        assert_eq!(scanner_stopped_detail(BluetoothError::Success),"扫描器已停止，旧距离证据已立即撤销");
        assert_eq!(scanner_stopped_detail(BluetoothError::RadioNotAvailable),
            "扫描器已停止（Windows 报告：蓝牙不可用），旧距离证据已立即撤销");
        assert_eq!(scanner_stopped_detail(BluetoothError(9999)),
            "扫描器已停止（Windows 报告：其他错误），旧距离证据已立即撤销");
    }
}
