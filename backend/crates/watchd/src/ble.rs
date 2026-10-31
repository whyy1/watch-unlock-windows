//! WinRT BLE advertisement scanner with explicit watcher lifecycle management.
//!
//! 直接使用 windows-rs 的 BluetoothLEAdvertisementWatcher：
//! watcher 复活逻辑需要对实例的完整控制，且本项目仅面向 Windows 单平台。

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementWatcher as WinRtAdvertisementWatcher, BluetoothLEScanningMode,
    BluetoothLEAdvertisementWatcherStoppedEventArgs,
};
use windows::Devices::Bluetooth::BluetoothError;
use windows::Foundation::{EventRegistrationToken, TypedEventHandler};
use windows::Storage::Streams::DataReader;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

/// 一条广播事件的精简表示。
#[derive(Debug, Clone)]
pub struct Advertisement {
    pub received_at: std::time::Instant,
    /// 6 字节蓝牙地址（canonical 序：首字节为最高有效字节）。
    pub address: [u8; 6],
    pub rssi: i16,
    /// Missing names stay unknown; manufacturer identity is not a device name.
    pub name: Option<String>,
    /// (公司 ID, 厂商数据) 列表。
    pub manufacturer: Vec<(u16, Vec<u8>)>,
}

impl Advertisement {
    pub fn address_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.address[4],
            self.address[5]
        )
    }
}

fn parse_event(
    args: &BluetoothLEAdvertisementReceivedEventArgs,
) -> windows::core::Result<Advertisement> {
    let addr64 = args.BluetoothAddress()?;
    let mut address = [0u8; 6];
    for (i, b) in address.iter_mut().enumerate() {
        *b = ((addr64 >> (40 - 8 * i)) & 0xFF) as u8;
    }
    let rssi = args.RawSignalStrengthInDBm()?;
    let mut manufacturer = Vec::new();
    let mut name = None;
    if let Ok(ad) = args.Advertisement() {
        name = ad.LocalName().ok().map(|n| n.to_string()).filter(|n| !n.trim().is_empty())
            .map(|n| n.chars().filter(|c| !c.is_control()).take(80).collect());
        if let Ok(data) = ad.ManufacturerData() {
            for m in data {
                if let (Ok(company), Ok(buf)) = (m.CompanyId(), m.Data()) {
                    let mut bytes = vec![0u8; buf.Length()? as usize];
                    DataReader::FromBuffer(&buf)?.ReadBytes(&mut bytes)?;
                    manufacturer.push((company, bytes));
                }
            }
        }
    }
    Ok(Advertisement {
        received_at: std::time::Instant::now(),
        address,
        rssi,
        name,
        manufacturer,
    })
}

/// Owns both the WinRT watcher and its event registration token.
///
/// `Stop()` alone does not release the event subscription.  Keeping the token
/// here makes every rebuild explicitly unregister the callback before the old
/// watcher is dropped, matching Microsoft's BLE watcher lifecycle guidance.
pub struct AdvertisementWatcher {
    watcher: WinRtAdvertisementWatcher,
    received_token: Option<EventRegistrationToken>,
    stopped_token: Option<EventRegistrationToken>,
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The BluetoothError Windows gave when it stopped the watcher on its own.
    stop_error: std::sync::Arc<std::sync::atomic::AtomicI32>,
}

impl AdvertisementWatcher {
    pub fn start(&self) -> windows::core::Result<()> {
        self.stopped.store(false, std::sync::atomic::Ordering::Relaxed);
        self.watcher.Start()
    }

    pub fn is_running(&self) -> bool {
        !self.stopped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Why Windows stopped the watcher, for the history line. `Success` when it gave no reason.
    pub fn stop_error(&self) -> BluetoothError {
        BluetoothError(self.stop_error.load(std::sync::atomic::Ordering::Acquire))
    }

    pub fn shutdown(&mut self) -> windows::core::Result<()> {
        let Some(token) = self.received_token.take() else {
            return Ok(());
        };
        let stop_result = self.watcher.Stop();
        let remove_result = self.watcher.RemoveReceived(token);
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(token) = self.stopped_token.take() { let _ = self.watcher.RemoveStopped(token); }

        match (stop_result, remove_result) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Drop for AdvertisementWatcher {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// 创建并绑定回调的 watcher（未 Start）。回调在 WinRT 线程池线程上触发。
pub fn make_watcher<F>(mut handler: F) -> windows::core::Result<AdvertisementWatcher>
where
    F: FnMut(&Advertisement) + Send + 'static,
{
    let watcher = WinRtAdvertisementWatcher::new()?;
    // Apple Nearby Info is manufacturer data in the primary advertisement.
    // Active mode only requests additional ScanResponse packets and causes
    // substantially more Bluetooth-stack work, so the daemon uses Passive.
    watcher.SetScanningMode(BluetoothLEScanningMode::Passive)?;
    let cb = TypedEventHandler::new(
        move |_sender: &Option<WinRtAdvertisementWatcher>,
              args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            if let Ok(adv) = parse_event(args) {
                handler(&adv);
            }
            Ok(())
        },
    );
    let received_token = watcher.Received(&cb)?;
    let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped_output = std::sync::Arc::clone(&stopped);
    let stop_error = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(BluetoothError::Success.0));
    let stop_error_output = std::sync::Arc::clone(&stop_error);
    let stopped_token = watcher.Stopped(&TypedEventHandler::new(
        move |_: &Option<WinRtAdvertisementWatcher>, args: &Option<BluetoothLEAdvertisementWatcherStoppedEventArgs>| {
            if let Some(error) = args.as_ref().and_then(|args| args.Error().ok()) {
                stop_error_output.store(error.0, std::sync::atomic::Ordering::Release);
            }
            stopped_output.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }))?;
    Ok(AdvertisementWatcher {
        watcher,
        received_token: Some(received_token),
        stopped_token: Some(stopped_token),
        stopped,
        stop_error,
    })
}

/// Fixed Chinese label for a Windows Bluetooth error; never the WinRT error text.
pub fn error_label(error: BluetoothError) -> &'static str {
    match error {
        BluetoothError::Success => "无",
        BluetoothError::RadioNotAvailable => "蓝牙不可用",
        BluetoothError::ResourceInUse => "资源被占用",
        BluetoothError::NotSupported => "不支持",
        BluetoothError::TransportNotSupported => "传输方式不支持",
        BluetoothError::DisabledByPolicy => "被策略禁止",
        BluetoothError::DisabledByUser => "被用户关闭",
        BluetoothError::ConsentRequired => "需要授权",
        BluetoothError::DeviceNotConnected => "设备未连接",
        _ => "其他错误",
    }
}

/// 扫描广播，每条经回调送出；`stop_after` 秒后停止（None = 直到 Ctrl+C）。
pub fn scan<F>(mut handler: F, stop_after: Option<u64>) -> anyhow::Result<()>
where
    F: FnMut(&Advertisement) + Send + 'static,
{
    // 控制台程序需显式初始化 COM 线程模型（失败则可能已初始化，忽略）
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let mut watcher = make_watcher(move |adv| handler(adv))?;
    watcher.start()?;
    tracing::info!("BLE 扫描已启动（Passive 模式）");

    match stop_after {
        Some(secs) => {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            let _ = watcher.shutdown();
            tracing::info!("扫描结束");
        }
        None => {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line); // Ctrl+C 直接终止
            let _ = watcher.shutdown();
        }
    }
    Ok(())
}

