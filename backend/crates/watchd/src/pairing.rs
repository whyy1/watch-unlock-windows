//! User-initiated Windows pairing window. No PairAsync/automatic acceptance or key export.

use std::borrow::Cow;
use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};
use serde::Serialize;
use windows::core::{RuntimeType, GUID};
use windows::Devices::Bluetooth::{BluetoothAdapter, BluetoothError, BluetoothLEDevice};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattReadRequest, GattReadRequestedEventArgs, GattServiceProvider,
    GattServiceProviderAdvertisementStatus, GattServiceProviderAdvertisementStatusChangedEventArgs,
    GattServiceProviderAdvertisingParameters, GattSession,
};
use windows::Devices::Radios::RadioState;
use windows::Foundation::{AsyncOperationCompletedHandler, AsyncStatus, EventRegistrationToken,
    IAsyncOperation, TypedEventHandler};
use windows::Storage::Streams::DataWriter;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
use windows::Win32::System::Console::{GetStdHandle, SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT,
    CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, STD_INPUT_HANDLE};
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

static CANCELLED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU32 = AtomicU32::new(0);
const REQUEST_NOT_SUPPORTED: u8 = 0x06;

#[derive(Serialize)]
struct PairingEvent {
    event: &'static str,
    status: &'static str,
    paired: bool,
    irk_verified: bool,
    watch_identity_verified: bool,
    advertising: &'static str,
    subscriptions: u32,
    encrypted_reads: u32,
    remaining_seconds: u64,
    reason: &'static str,
}

fn event(status: &'static str, state: &Snapshot, reason: &'static str) -> PairingEvent {
    PairingEvent { event: "pairing_window", status, paired: state.paired,
        irk_verified: false, watch_identity_verified: false, advertising: state.advertising,
        subscriptions: state.subscriptions, encrypted_reads: state.encrypted_reads,
        remaining_seconds: state.remaining_seconds, reason }
}

fn emit(value: PairingEvent) {
    // Only fixed labels/counts are serialized. Never stringify WinRT objects or errors.
    if let Ok(line) = serde_json::to_string(&value) {
        let mut output = std::io::stdout().lock();
        let _ = writeln!(output, "{line}");
        let _ = output.flush();
    }
}

#[derive(Default)]
struct Snapshot {
    paired: bool,
    advertising: &'static str,
    subscriptions: u32,
    encrypted_reads: u32,
    remaining_seconds: u64,
    /// Seconds the advertisement was fully running, and how it went, for the history line.
    advertised_seconds: u64,
    limited: bool,
    restarts: u32,
    advertising_error: i32,
    advertising_opened: bool,
}

struct Apartment;
impl Drop for Apartment { fn drop(&mut self) { unsafe { RoUninitialize(); } } }

struct ConsoleGuard;
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        unsafe { let _ = SetConsoleCtrlHandler(Some(cancel_handler), false); }
        RUNNING.store(false, Ordering::Release);
    }
}

unsafe extern "system" fn cancel_handler(kind: u32) -> BOOL {
    if matches!(kind, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT) {
        CANCELLED.store(true, Ordering::Release);
        true.into()
    } else { false.into() }
}

fn listen_for_cancel(generation: u32) {
    let is_pipe = unsafe { GetStdHandle(STD_INPUT_HANDLE).map(|handle| GetFileType(handle) == FILE_TYPE_PIPE) }.unwrap_or(false);
    if !is_pipe { return; }
    std::thread::spawn(move || {
        let mut input = std::io::BufReader::new(std::io::stdin().take(32));
        let mut command = Vec::new();
        if input.read_until(b'\n', &mut command).is_ok()
            && matches!(command.as_slice(), b"cancel\n" | b"cancel\r\n")
            && RUNNING.load(Ordering::Acquire) && GENERATION.load(Ordering::Acquire) == generation {
            CANCELLED.store(true, Ordering::Release);
        }
    });
}

fn wait<T: RuntimeType + 'static>(operation: IAsyncOperation<T>, deadline: Instant) -> Result<T> {
    loop {
        if CANCELLED.load(Ordering::Acquire) || Instant::now() >= deadline {
            let _ = operation.Cancel();
            bail!("Pairing operation cancelled or timed out");
        }
        match operation.Status()? {
            AsyncStatus::Completed => return Ok(operation.GetResults()?),
            AsyncStatus::Started => std::thread::sleep(Duration::from_millis(25)),
            _ => bail!("Pairing operation unavailable"),
        }
    }
}

fn operation_deadline(end: Instant, seconds: u64) -> Instant {
    end.min(Instant::now() + Duration::from_secs(seconds))
}

fn bluetooth_uuid(value: u16) -> GUID {
    GUID::from_u128(((value as u128) << 96) | 0x0000_1000_8000_0080_5f9b_34fb)
}

#[derive(Default)]
struct ReadState {
    closing: AtomicBool,
    in_flight: AtomicU32,
    count: AtomicU32,
    session: Mutex<Option<GattSession>>,
    /// The BluetoothError Windows gave with the last advertisement status change.
    advertising_error: AtomicI32,
}

struct PairingWindow {
    provider: GattServiceProvider,
    measurement: GattLocalCharacteristic,
    read_token: Option<EventRegistrationToken>,
    status_token: Option<EventRegistrationToken>,
    reads: Arc<ReadState>,
}

impl Drop for PairingWindow {
    fn drop(&mut self) {
        self.reads.closing.store(true, Ordering::Release);
        let _ = self.provider.StopAdvertising();
        if let Some(token) = self.read_token.take() {
            let _ = self.measurement.RemoveReadRequested(token);
        }
        if let Some(token) = self.status_token.take() {
            let _ = self.provider.RemoveAdvertisementStatusChanged(token);
        }
    }
}

fn read_handler(reads: Arc<ReadState>) -> TypedEventHandler<GattLocalCharacteristic, GattReadRequestedEventArgs> {
    TypedEventHandler::new(move |_, arguments: &Option<GattReadRequestedEventArgs>| {
        let Some(arguments) = arguments else { return Ok(()); };
        if reads.closing.load(Ordering::Acquire) { return Ok(()); }
        if reads.in_flight.fetch_add(1, Ordering::AcqRel) >= 16 {
            reads.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Ok(());
        }
        let deferral = match arguments.GetDeferral() {
            Ok(value) => value,
            Err(_) => { reads.in_flight.fetch_sub(1, Ordering::AcqRel); return Ok(()); },
        };
        let operation = match arguments.GetRequestAsync() {
            Ok(value) => value,
            Err(_) => {
                let _ = deferral.Complete();
                reads.in_flight.fetch_sub(1, Ordering::AcqRel);
                return Ok(());
            },
        };
        let session = arguments.Session().ok();
        let completion_deferral = deferral.clone();
        let completed_reads = reads.clone();
        let callback = AsyncOperationCompletedHandler::<GattReadRequest>::new(move |operation, _| {
            if let Some(operation) = operation {
                if let Ok(request) = operation.GetResults() {
                    // Encryption is enforced by Windows before dispatching this read.
                    // This PC has no heart-rate sensor and never supplies fake measurements.
                    if request.RespondWithProtocolError(REQUEST_NOT_SUPPORTED).is_ok()
                        && !completed_reads.closing.load(Ordering::Acquire) {
                        completed_reads.count.fetch_add(1, Ordering::AcqRel);
                        if let Ok(mut latest) = completed_reads.session.lock() { *latest = session.clone(); }
                    }
                }
            }
            let _ = completion_deferral.Complete();
            completed_reads.in_flight.fetch_sub(1, Ordering::AcqRel);
            Ok(())
        });
        if operation.SetCompleted(&callback).is_err() {
            let _ = deferral.Complete();
            reads.in_flight.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(())
    })
}

fn create_window(end: Instant) -> Result<PairingWindow> {
    let service = wait(GattServiceProvider::CreateAsync(bluetooth_uuid(0x180d))?, operation_deadline(end, 15))?;
    ensure!(service.Error()? == BluetoothError::Success, "Pairing service unavailable");
    let provider = service.ServiceProvider()?;
    let measurement = GattLocalCharacteristicParameters::new()?;
    measurement.SetCharacteristicProperties(GattCharacteristicProperties::Read | GattCharacteristicProperties::Notify)?;
    measurement.SetReadProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    measurement.SetWriteProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    let result = wait(provider.Service()?.CreateCharacteristicAsync(bluetooth_uuid(0x2a37), &measurement)?, operation_deadline(end, 15))?;
    ensure!(result.Error()? == BluetoothError::Success, "Pairing characteristic unavailable");
    let reads = Arc::new(ReadState::default());
    let mut window = PairingWindow { provider, measurement: result.Characteristic()?, read_token: None, status_token: None, reads };
    window.read_token = Some(window.measurement.ReadRequested(&read_handler(window.reads.clone()))?);
    let status = window.reads.clone();
    // Only feeds the failure reason, so a system that refuses the subscription still pairs.
    window.status_token = window.provider.AdvertisementStatusChanged(&TypedEventHandler::new(
        move |_, arguments: &Option<GattServiceProviderAdvertisementStatusChangedEventArgs>| {
            if let Some(error) = arguments.as_ref().and_then(|arguments| arguments.Error().ok()) {
                status.advertising_error.store(error.0, Ordering::Release);
            }
            Ok(())
        })).ok();
    let writer = DataWriter::new()?;
    writer.WriteByte(0)?; // Body Sensor Location: Other. This is not a heart-rate value.
    let location = GattLocalCharacteristicParameters::new()?;
    location.SetCharacteristicProperties(GattCharacteristicProperties::Read)?;
    location.SetReadProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    location.SetStaticValue(&writer.DetachBuffer()?)?;
    writer.Close()?;
    let result = wait(window.provider.Service()?.CreateCharacteristicAsync(bluetooth_uuid(0x2a38), &location)?, operation_deadline(end, 15))?;
    ensure!(result.Error()? == BluetoothError::Success, "Pairing location characteristic unavailable");
    Ok(window)
}

fn verified_pairing(session: &GattSession, end: Instant) -> bool {
    let result = (|| -> Result<bool> {
        let id = session.DeviceId()?.Id()?;
        let device = wait(BluetoothLEDevice::FromIdAsync(&id)?, operation_deadline(end, 2))?;
        let paired = device.DeviceInformation().and_then(|info| info.Pairing()).and_then(|pairing| pairing.IsPaired());
        let _ = device.Close();
        Ok(paired?)
    })();
    result.unwrap_or(false)
}

fn advertising_label(status: GattServiceProviderAdvertisementStatus) -> &'static str {
    match status {
        GattServiceProviderAdvertisementStatus::Started => "started",
        GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData => "limited",
        GattServiceProviderAdvertisementStatus::Aborted => "aborted",
        GattServiceProviderAdvertisementStatus::Stopped => "stopped",
        GattServiceProviderAdvertisementStatus::Created => "created",
        _ => "unknown",
    }
}

/// Why a pairing window could not run. Fixed labels only: the UI maps each to an explanation
/// and a fix, and no WinRT error text ever leaves the process.
#[derive(Debug)]
struct Unavailable(&'static str);
impl std::fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str(self.0) }
}
impl std::error::Error for Unavailable {}

fn unavailable(reason: &'static str) -> anyhow::Error { Unavailable(reason).into() }

const ADVERTISING_RESTARTS: u32 = 3;
const ABORT_BEFORE_START: Duration = Duration::from_secs(15);
const ABORT_AFTER_START: Duration = Duration::from_secs(3);

fn open_window(end: Instant, discoverable: bool) -> Result<PairingWindow> {
    let window = create_window(end).map_err(|_| unavailable("service_failed"))?;
    let parameters = GattServiceProviderAdvertisingParameters::new()?;
    parameters.SetIsConnectable(true)?;
    parameters.SetIsDiscoverable(discoverable)?;
    window.provider.StartAdvertisingWithParameters(&parameters).map_err(|_| unavailable("service_failed"))?;
    Ok(window)
}

fn run_window(seconds: u64, state: &mut Snapshot) -> Result<&'static str> {
    let end = Instant::now() + Duration::from_secs(seconds);
    unsafe { RoInitialize(RO_INIT_MULTITHREADED)?; }
    let _apartment = Apartment;
    // Preflight in the order a user can act on: adapter, radio, then the capabilities pairing needs.
    let adapter = BluetoothAdapter::GetDefaultAsync().ok()
        .and_then(|operation| wait(operation, operation_deadline(end, 15)).ok())
        .ok_or_else(|| unavailable("no_adapter"))?;
    let radio = wait(adapter.GetRadioAsync()?, operation_deadline(end, 15)).map_err(|_| unavailable("no_adapter"))?;
    if radio.State()? != RadioState::On { return Err(unavailable("radio_off")); }
    if !adapter.IsLowEnergySupported()? { return Err(unavailable("le_unsupported")); }
    if !adapter.IsPeripheralRoleSupported()? { return Err(unavailable("peripheral_unsupported")); }
    let mut window = open_window(end, true)?;
    state.advertising_opened = true;
    let mut restarts = 0;
    let mut started = false;
    // Whether the current advertisement has run; a rebuilt one gets the startup allowance again.
    let mut live = false;
    let mut next_tally = Instant::now();
    let mut next_report = Instant::now();
    let mut next_verify = Instant::now();
    let mut aborted_since: Option<Instant> = None;
    loop {
        if CANCELLED.load(Ordering::Acquire) { return Ok("cancelled"); }
        if Instant::now() >= end { return Ok("timeout"); }
        let now = Instant::now();
        let status = window.provider.AdvertisementStatus()?;
        state.advertising = advertising_label(status);
        state.remaining_seconds = end.saturating_duration_since(now).as_secs();
        state.encrypted_reads = window.reads.count.load(Ordering::Acquire);
        let clients = window.measurement.SubscribedClients()?;
        state.subscriptions = clients.Size()?;
        if status == GattServiceProviderAdvertisementStatus::Aborted {
            let since = *aborted_since.get_or_insert(now);
            // Windows reports Aborted while a new advertisement is still starting, briefly on fast
            // adapters and for seconds on slow ones. Only a drop after it ran gets the short limit.
            let limit = if live { ABORT_AFTER_START } else { ABORT_BEFORE_START };
            if now.duration_since(since) >= limit {
                // Some adapters abort the first advertisement and accept a fresh one. Rebuild the
                // service; the last try leaves out the discoverable flag, which some drivers reject.
                if restarts >= ADVERTISING_RESTARTS {
                    return Err(unavailable(abort_reason(BluetoothError(window.reads.advertising_error.load(Ordering::Acquire)))));
                }
                restarts += 1;
                drop(window);
                std::thread::sleep(Duration::from_millis(500));
                window = open_window(end, restarts < ADVERTISING_RESTARTS)?;
                aborted_since = None;
                live = false;
                continue;
            }
        } else { aborted_since = None; }
        let running = matches!(status, GattServiceProviderAdvertisementStatus::Started
            | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData);
        live |= running;
        state.limited |= status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData;
        if status == GattServiceProviderAdvertisementStatus::Started && now >= next_tally {
            state.advertised_seconds += 1;
            next_tally = now + Duration::from_secs(1);
        }
        state.restarts = restarts;
        state.advertising_error = window.reads.advertising_error.load(Ordering::Acquire);
        if running && !started {
            started = true;
            emit(event("started", state, "user_confirmation_required"));
        }
        if now >= next_verify {
            next_verify = now + Duration::from_secs(1);
            // Subscription alone never proves an encrypted link. Verify the exact
            // peer session that completed an EncryptionRequired measurement read.
            let recent = window.reads.session.lock().ok().and_then(|value| value.clone());
            // A watch may only subscribe (an encrypted descriptor write) and never read, so the
            // subscribed sessions are checked too; Windows' bond state decides either way.
            let subscribed = clients.into_iter().take(4).filter_map(|client| client.Session().ok());
            state.paired = recent.into_iter().chain(subscribed).any(|session| verified_pairing(&session, end));
            if state.paired { return Ok("bond_verified_identity_not_imported"); }
        }
        if now >= next_report {
            emit(event("waiting", state, "user_confirmation_required"));
            next_report = now + Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Advertise only in response to an explicit pairing action, for at most 120 seconds.
/// Read-only Bluetooth facts for the diagnostics report: the same checks as the pairing preflight.
pub fn bluetooth_report() -> Vec<(&'static str, Cow<'static, str>)> {
    fn answer(value: windows::core::Result<bool>) -> &'static str {
        match value { Ok(true) => "是", Ok(false) => "否", Err(_) => "无法读取" }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    if unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.is_err() { return vec![("蓝牙", "无法读取".into())]; }
    let _apartment = Apartment;
    let Some(adapter) = BluetoothAdapter::GetDefaultAsync().ok().and_then(|operation| wait(operation, deadline).ok()) else {
        return vec![("蓝牙适配器", "没有找到".into())];
    };
    let radio = adapter.GetRadioAsync().ok().and_then(|operation| wait(operation, deadline).ok())
        .and_then(|radio| radio.State().ok());
    let radio = match radio {
        Some(state) if state == RadioState::On => "已打开",
        Some(state) if state == RadioState::Off => "已关闭",
        Some(state) if state == RadioState::Disabled => "已禁用",
        Some(_) => "未知",
        None => "无法读取",
    };
    let hardware = adapter.DeviceId().ok().and_then(|id| hardware_id(&id.to_string_lossy()));
    vec![
        ("蓝牙适配器", "已找到".into()),
        ("适配器硬件", hardware.map_or("无法读取".into(), Cow::Owned)),
        ("蓝牙开关", radio.into()),
        ("低功耗蓝牙", answer(adapter.IsLowEnergySupported()).into()),
        ("外设模式（配对需要）", answer(adapter.IsPeripheralRoleSupported()).into()),
        ("中心模式（扫描需要）", answer(adapter.IsCentralRoleSupported()).into()),
    ]
}

/// One history line on how the advertisement went: the watch can only find a PC whose full
/// heart-rate advertisement is on air. Built from counts and fixed labels only.
fn advertising_summary(state: &Snapshot) -> String {
    let error = crate::ble::error_label(BluetoothError(state.advertising_error));
    format!("配对广播：完整广播 {} 秒{}，重建 {} 次，Windows 报告的错误：{}",
        state.advertised_seconds,
        if state.limited { "，曾出现广播内容不完整（手表可能认不出）" } else { "" },
        state.restarts, error)
}

/// Windows names why it stopped an advertisement; turn that into a reason the user can act on.
fn abort_reason(error: BluetoothError) -> &'static str {
    match error {
        BluetoothError::RadioNotAvailable => "radio_off",
        BluetoothError::ResourceInUse => "advertising_busy",
        BluetoothError::NotSupported | BluetoothError::TransportNotSupported => "peripheral_unsupported",
        BluetoothError::DisabledByPolicy | BluetoothError::DisabledByUser | BluetoothError::ConsentRequired => "advertising_blocked",
        _ => "advertising_aborted",
    }
}

/// Bus and vendor/product IDs from an adapter interface path such as
/// `\\?\USB#VID_8087&PID_0026#5&1a2b#{...}`: they name the chip and driver family that
/// matter for advertising. The instance part, which can identify this machine, is dropped.
fn hardware_id(interface: &str) -> Option<String> {
    let mut parts = interface.trim_start_matches(r"\\?\").split('#');
    let bus = parts.next()?;
    let ids = parts.next()?;
    let plain = |part: &str| !part.is_empty() && part.len() <= 48
        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'&' || b == b'_');
    (plain(bus) && plain(ids) && (ids.contains("VID_") || ids.contains("VEN_")))
        .then(|| format!("{bus} {ids}"))
}

/// History line for a closed pairing window. Fixed text only; a cancelled window is not recorded.
fn outcome_detail(paired: bool, reason: &str, watch_connected: bool) -> Option<(&'static str, &'static str)> {
    if paired { return Some(("pairing_completed", "Windows 已与手表完成配对")); }
    let detail = match reason {
        "no_adapter" => "配对未完成：没有找到蓝牙适配器",
        "radio_off" => "配对未完成：蓝牙已关闭",
        "le_unsupported" => "配对未完成：蓝牙不支持低功耗蓝牙",
        "peripheral_unsupported" => "配对未完成：蓝牙适配器不支持外设模式",
        "service_failed" => "配对未完成：无法开启配对服务",
        "advertising_aborted" => "配对未完成：配对广播被系统中断（已自动重试 3 次）",
        "advertising_busy" => "配对未完成：蓝牙广播被其他程序或系统功能占用（已自动重试 3 次）",
        "advertising_blocked" => "配对未完成：蓝牙广播被系统策略或隐私设置禁止",
        "timeout" if watch_connected => "配对未完成：手表已连接，但 Windows 没有确认配对（可能漏点了配对通知）",
        "timeout" => "配对未完成：手表没有连接这台电脑，或连接后没有完成配对",
        "cancelled" => return None,
        _ => "配对未完成：配对窗口无法开启",
    };
    Some(("pairing_failed", detail))
}

pub fn run(seconds: u64) -> Result<()> {
    ensure!((1..=120).contains(&seconds), "Pairing duration must be from 1 to 120 seconds");
    ensure!(!RUNNING.swap(true, Ordering::AcqRel), "A pairing window is already active");
    CANCELLED.store(false, Ordering::Release);
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    let _console = ConsoleGuard;
    unsafe { let _ = SetConsoleCtrlHandler(Some(cancel_handler), true); }
    listen_for_cancel(generation);
    let mut state = Snapshot { advertising: "created", remaining_seconds: seconds, ..Default::default() };
    emit(event("waiting", &state, "preparing"));
    let result = run_window(seconds, &mut state);
    state.advertising = "stopped";
    state.remaining_seconds = 0;
    let reason = match &result {
        Ok(reason) => reason,
        Err(_) if CANCELLED.load(Ordering::Acquire) => "cancelled",
        Err(error) => error.downcast_ref::<Unavailable>().map_or("unavailable", |reason| reason.0),
    };
    emit(event("stopped", &state, reason));
    let watch_connected = state.subscriptions > 0 || state.encrypted_reads > 0;
    if let Some((name, detail)) = outcome_detail(state.paired, reason, watch_connected) {
        crate::audit::record(name, None, detail);
    }
    if state.advertising_opened {
        crate::audit::record("pairing_advertising", None, &advertising_summary(&state));
    }
    result.map(|_| ()).map_err(|_| anyhow::anyhow!("Pairing window unavailable; check Bluetooth and BLE peripheral support"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertising_summary_uses_counts_and_fixed_labels() {
        let state = Snapshot { advertised_seconds: 0, limited: true, restarts: 3,
            advertising_error: BluetoothError::ResourceInUse.0, ..Default::default() };
        assert_eq!(advertising_summary(&state),
            "配对广播：完整广播 0 秒，曾出现广播内容不完整（手表可能认不出），重建 3 次，Windows 报告的错误：资源被占用");
    }

    #[test]
    fn advertising_errors_name_an_actionable_reason() {
        assert_eq!(abort_reason(BluetoothError::ResourceInUse), "advertising_busy");
        assert_eq!(abort_reason(BluetoothError::RadioNotAvailable), "radio_off");
        assert_eq!(abort_reason(BluetoothError::DisabledByPolicy), "advertising_blocked");
        assert_eq!(abort_reason(BluetoothError::Success), "advertising_aborted");
        for reason in ["advertising_busy", "advertising_blocked"] {
            assert!(outcome_detail(false, reason, false).is_some_and(|o| !o.1.ends_with("无法开启")));
        }
    }

    #[test]
    fn hardware_id_keeps_vendor_and_product_only() {
        assert_eq!(hardware_id(r"\\?\USB#VID_8087&PID_0026#5&2b4c1a&0&10#{92383b0e-f90e-4ac9-8d44-8c2d0d0ebda2}").as_deref(),
            Some("USB VID_8087&PID_0026"));
        assert_eq!(hardware_id(r"\\?\PCI#VEN_14E4&DEV_43A0#4&1234#{x}").as_deref(), Some("PCI VEN_14E4&DEV_43A0"));
        assert_eq!(hardware_id(r"\\?\BTHENUM#{0000}_LOCALMFG#7&1"), None);
        assert_eq!(hardware_id("garbage"), None);
    }

    #[test]
    fn closed_windows_are_recorded_except_when_cancelled() {
        assert_eq!(outcome_detail(true, "timeout", true).map(|o| o.0), Some("pairing_completed"));
        assert_eq!(outcome_detail(false, "cancelled", true), None);
        assert_eq!(outcome_detail(false, "radio_off", false).map(|o| o.0), Some("pairing_failed"));
        // A connected watch without a bond points at the missed Windows toast.
        assert_ne!(outcome_detail(false, "timeout", true), outcome_detail(false, "timeout", false));
    }

    #[test]
    fn failure_reasons_survive_as_fixed_labels() {
        for reason in ["no_adapter", "radio_off", "le_unsupported", "peripheral_unsupported", "service_failed", "advertising_aborted"] {
            let error = unavailable(reason);
            assert_eq!(error.downcast_ref::<Unavailable>().map(|value| value.0), Some(reason));
        }
        assert!(anyhow::anyhow!("other").downcast_ref::<Unavailable>().is_none());
    }

    #[test]
    fn invalid_duration_does_not_touch_bluetooth() {
        assert!(run(0).is_err());
        assert!(run(121).is_err());
    }

    #[test]
    fn advertised_state_and_subscription_counts_never_claim_a_verified_bond() {
        let state = Snapshot { advertising: "started", subscriptions: 1, encrypted_reads: 1,
            remaining_seconds: 100, ..Default::default() };
        let json = serde_json::to_value(event("waiting", &state, "user_confirmation_required")).unwrap();
        assert_eq!(json["paired"], false);
        assert_eq!(json["irk_verified"], false);
        assert_eq!(json["watch_identity_verified"], false);
        assert!(json.get("device_id").is_none());
        assert!(json.get("address").is_none());
    }

    #[test]
    fn standard_service_uuids_use_the_bluetooth_base() {
        assert_eq!(bluetooth_uuid(0x180d), GUID::from_u128(0x0000180d_0000_1000_8000_00805f9b34fb));
        assert_eq!(REQUEST_NOT_SUPPORTED, 0x06);
    }
}
