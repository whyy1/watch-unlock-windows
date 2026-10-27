//! Windows Credential Provider implemented with Rust COM.
//!
//! 宿主 LogonUI.exe（SYSTEM / secure desktop）。工作方式：
//! 1. SetUsageScenario(CPUS_LOGON / CPUS_UNLOCK_WORKSTATION) → 启动管道握手线程；
//! 2. 守护验证远离返回或显式批准后，向已验证的管道连接提交一次请求；
//! 3. 显示 Watch Unlock 磁贴并自动调用 GetSerialization → LSA 校验 → 解锁。
//!
//! 故障安全：无信号时报告 0 凭据，完全不干扰系统自带密码框。

mod events;
mod pipe;
mod secret;

use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

use windows::core::Interface;
use windows::core::{
    implement, ComObject, IUnknown, IUnknownImpl, Type, GUID, PCWSTR, PSTR, PWSTR,
};
use windows::Win32::Foundation::{
    BOOL, CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_INVALIDARG, E_NOTIMPL,
    E_OUTOFMEMORY, HANDLE, NTSTATUS,
};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Authentication::Identity::{
    KerbInteractiveLogon, KerbWorkstationUnlockLogon, LsaConnectUntrusted,
    LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, KERB_INTERACTIVE_UNLOCK_LOGON,
    LSA_STRING, LSA_UNICODE_STRING,
};
use windows::Win32::Security::Credentials::CredProtectW;
use windows::Win32::System::Com::{
    CoTaskMemAlloc, CoTaskMemFree, IClassFactory, IClassFactory_Impl,
};
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, ICredentialProviderEvents, ICredentialProvider_Impl,
    SHStrDupW, CPFG_CREDENTIAL_PROVIDER_LABEL, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_HIDDEN,
    CPFT_LARGE_TEXT, CPFT_SMALL_TEXT, CPGSR_RETURN_CREDENTIAL_FINISHED, CPUS_LOGON,
    CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

/// 组件 CLSID（固定，注册表用）；与上游不同，避免和其他版本的登录组件冲突。
pub const CLSID: GUID = GUID::from_u128(0xa8ca66e1_5fca_45dd_8d79_44fc9701b739);

/// Read-only production trust check, also used by the negative integration test.
pub fn is_trusted_daemon_pipe(handle: windows::Win32::Foundation::HANDLE) -> bool {
    pipe::is_trusted_server(handle)
}

const FIELD_PROVIDER_LABEL: u32 = 0;
const FIELD_TILE_TITLE: u32 = 1;
const FIELD_COUNT: u32 = 2;

fn clear_secret(value: &mut String) {
    let ptr = value.as_mut_ptr();
    for index in 0..value.len() {
        unsafe { std::ptr::write_volatile(ptr.add(index), 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

fn field_text(field_id: u32) -> windows::core::Result<PWSTR> {
    match field_id {
        FIELD_PROVIDER_LABEL | FIELD_TILE_TITLE => unsafe {
            SHStrDupW(windows::core::w!("Watch Unlock"))
        },
        _ => Err(E_INVALIDARG.into()),
    }
}

fn allocate_field_descriptor(
    field_id: u32,
) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let (field_type, guid) = match field_id {
        FIELD_PROVIDER_LABEL => (CPFT_SMALL_TEXT, CPFG_CREDENTIAL_PROVIDER_LABEL),
        FIELD_TILE_TITLE => (CPFT_LARGE_TEXT, GUID::default()),
        _ => return Err(E_INVALIDARG.into()),
    };
    let label = field_text(field_id)?;
    let raw = unsafe { CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) }
        as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
    if raw.is_null() {
        unsafe { CoTaskMemFree(Some(label.0.cast())) };
        return Err(E_OUTOFMEMORY.into());
    }
    unsafe {
        raw.write(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: field_id,
            cpft: field_type,
            pszLabel: label,
            guidFieldType: guid,
        });
    }
    Ok(raw)
}

/// 毒锁恢复：任何 panic 后的锁仍可继续使用，避免连锁崩溃。
fn lock_ok<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Shared data contains no apartment-bound COM pointers.
struct State {
    usage: Mutex<Option<CREDENTIAL_PROVIDER_USAGE_SCENARIO>>,
    signal: Mutex<Option<pipe::UnlockSignal>>,
    events: events::Events,
    /// Permanent: set on destruction or an unsupported scenario. Advise fails afterwards.
    stop: Arc<AtomicBool>,
    /// Stop flag of the current pipe worker. UnAdvise only pauses: LogonUI may hide the tile
    /// (for example the extra lock-screen layer after Windows Dynamic Lock) and Advise again.
    link: Mutex<Arc<AtomicBool>>,
    submitted: AtomicBool,
}

impl State {
    fn ready(&self) -> bool {
        !self.stop.load(Ordering::Acquire)
            && !self.submitted.load(Ordering::Acquire)
            && lock_ok(&self.signal).is_some()
    }

    fn cancel(&self) {
        self.stop.store(true, Ordering::Release);
        self.pause();
    }

    /// Drops the pipe connection and any undelivered credential; a later Advise reconnects.
    fn pause(&self) {
        lock_ok(&self.link).store(true, Ordering::Release);
        lock_ok(&self.signal).take();
        self.events.unadvise();
    }

    fn claim_submission(&self) -> windows::core::Result<pipe::UnlockSignal> {
        if self.stop.load(Ordering::Acquire) || self.submitted.swap(true, Ordering::AcqRel) {
            return Err(E_FAIL.into());
        }
        lock_ok(&self.signal).take().ok_or_else(|| E_FAIL.into())
    }
}

#[implement(ICredentialProvider, ICredentialProviderCredential)]
struct WatchUnlockProvider {
    state: Arc<State>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl WatchUnlockProvider {
    fn new() -> Self {
        Self {
            state: Arc::new(State {
                usage: Mutex::new(None),
                signal: Mutex::new(None),
                events: events::Events::default(),
                stop: Arc::new(AtomicBool::new(false)),
                link: Mutex::new(Arc::new(AtomicBool::new(true))),
                submitted: AtomicBool::new(false),
            }),
            worker: Mutex::new(None),
        }
    }
}

impl WatchUnlockProvider {
    /// Starts a pipe worker unless one is connected or a credential is already waiting.
    fn connect_worker(&self) -> windows::core::Result<()> {
        if self.state.stop.load(Ordering::Acquire) {
            return Err(E_FAIL.into());
        }
        let mut worker = lock_ok(&self.worker);
        let mut link = lock_ok(&self.state.link);
        let running = !link.load(Ordering::Acquire) && worker.as_ref().is_some_and(|handle| !handle.is_finished());
        if running || lock_ok(&self.state.signal).is_some() {
            return Ok(());
        }
        let current = Arc::new(AtomicBool::new(false));
        *link = current.clone();
        drop(link);
        let state = self.state.clone();
        let paused = current.clone();
        let handle = pipe::run_pipe_client(current, move |signal| {
            {
                let mut pending = lock_ok(&state.signal);
                if state.stop.load(Ordering::Acquire) || paused.load(Ordering::Acquire)
                    || state.submitted.load(Ordering::Acquire) {
                    return;
                }
                *pending = Some(signal);
            }
            if !state.stop.load(Ordering::Acquire) {
                state.events.notify();
            }
        }).map_err(|_| windows::core::Error::from(E_FAIL))?;
        *worker = Some(handle);
        Ok(())
    }
}

impl Drop for WatchUnlockProvider {
    fn drop(&mut self) {
        self.state.cancel();
        // Do not join an RPC callback on its target apartment. The worker owns
        // only Arc<State>, polls cancellation, and the DLL reports S_FALSE.
    }
}

// ---------- KERB 序列化组装（独立函数便于单测） ----------

/// 将用户名、域和密码打包进同一块 CoTaskMem 缓冲区。
///
/// Winlogon/LSA 要求 LSA_UNICODE_STRING.Buffer 是相对整个序列化缓冲区的字节偏移，
/// 不能是 LogonUI 进程中的裸指针。布局与微软 Credential Provider 示例一致。
pub fn build_unlock_serialization(
    username: &str,
    password: &str,
    domain: &str,
    message_type: windows::Win32::Security::Authentication::Identity::KERB_LOGON_SUBMIT_TYPE,
) -> Result<(*mut u8, u32), windows::core::Error> {
    let domain_units: Vec<u16> = domain.encode_utf16().collect();
    let user_units: Vec<u16> = username.encode_utf16().collect();
    let password_units = secret::Wide(password.encode_utf16().collect());
    let byte_len = |units: &[u16]| -> windows::core::Result<u16> {
        units
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| E_INVALIDARG.into())
    };
    let domain_len = byte_len(&domain_units)?;
    let user_len = byte_len(&user_units)?;
    let password_len = byte_len(&password_units)?;
    let header_size = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    let size = header_size
        .checked_add(domain_len as usize)
        .and_then(|n| n.checked_add(user_len as usize))
        .and_then(|n| n.checked_add(password_len as usize))
        .ok_or_else(|| windows::core::Error::from(E_INVALIDARG))?;
    let size_u32 = u32::try_from(size).map_err(|_| windows::core::Error::from(E_INVALIDARG))?;
    let raw = unsafe { CoTaskMemAlloc(size) as *mut u8 };
    if raw.is_null() {
        return Err(E_OUTOFMEMORY.into());
    }
    unsafe {
        std::ptr::write_bytes(raw, 0, size);
        let packed = &mut *(raw as *mut KERB_INTERACTIVE_UNLOCK_LOGON);
        packed.Logon.MessageType = message_type;

        let mut offset = header_size;
        let mut copy_string = |units: &[u16], len: u16| -> LSA_UNICODE_STRING {
            if !units.is_empty() {
                std::ptr::copy_nonoverlapping(
                    units.as_ptr(),
                    raw.add(offset) as *mut u16,
                    units.len(),
                );
            }
            let value = LSA_UNICODE_STRING {
                Length: len,
                MaximumLength: len,
                Buffer: PWSTR(offset as *mut u16),
            };
            offset += len as usize;
            value
        };
        packed.Logon.LogonDomainName = copy_string(&domain_units, domain_len);
        packed.Logon.UserName = copy_string(&user_units, user_len);
        packed.Logon.Password = copy_string(&password_units, password_len);
        // 官方打包格式把 LogonId 清零，由 Winlogon 根据当前场景填充/解释。
        packed.LogonId = Default::default();
    }
    Ok((raw, size_u32))
}

/// 登录/解锁场景中先用 CredProtect 保护密码，再交给 Winlogon。
fn protect_password(password: &str) -> windows::core::Result<String> {
    let input = secret::Wide(password.encode_utf16().chain(std::iter::once(0)).collect());
    let mut required = 0u32;
    let _ = unsafe { CredProtectW(false, &input, PWSTR::null(), &mut required, None) };
    if required == 0 {
        return Err(E_FAIL.into());
    }
    let mut protected = secret::Wide(vec![0u16; required as usize]);
    unsafe {
        CredProtectW(
            false,
            &input,
            PWSTR(protected.as_mut_ptr()),
            &mut required,
            None,
        )?;
    }
    let end = protected
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(protected.len());
    String::from_utf16(&protected[..end]).map_err(|_| E_FAIL.into())
}

/// 查询 Negotiate 认证包编号；编号由 LSA 动态分配，不能硬编码为 0。
pub fn retrieve_negotiate_auth_package() -> windows::core::Result<u32> {
    let mut lsa = HANDLE::default();
    unsafe {
        LsaConnectUntrusted(&mut lsa).ok()?;
    }
    let name = b"Negotiate";
    let lsa_name = LSA_STRING {
        Length: name.len() as u16,
        MaximumLength: (name.len() + 1) as u16,
        Buffer: PSTR(name.as_ptr() as *mut u8),
    };
    let mut package = 0u32;
    let result = unsafe { LsaLookupAuthenticationPackage(lsa, &lsa_name, &mut package).ok() };
    unsafe {
        let _ = LsaDeregisterLogonProcess(lsa);
    }
    result?;
    Ok(package)
}

// LogonUI must not open a user-writable fixed pathname as SYSTEM.
// The host may install a tracing subscriber; this DLL creates no log files.

// ---------- ICredentialProvider_Impl（挂在生成的 shim 上） ----------

impl ICredentialProvider_Impl for WatchUnlockProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> windows::core::Result<()> {
        if cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION {
            self.state.cancel();
            return Err(E_NOTIMPL.into());
        }
        if self.state.stop.load(Ordering::Acquire) {
            return Err(E_FAIL.into());
        }
        *lock_ok(&self.state.usage) = Some(cpus);
        self.connect_worker()
    }

    fn SetSerialization(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        // 本 provider 只接受手表守护经管道送达的凭据，不消费其他 provider 的序列化。
        if !pcpcs.is_null() {
            tracing::info!("[PROVIDER] 忽略外部 SetSerialization");
        }
        Ok(())
    }

    fn Advise(
        &self,
        pcpe: Option<&ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        if self.state.stop.load(Ordering::Acquire) { return Err(E_FAIL.into()); }
        self.state.events.advise(pcpe, upadvisecontext)?;
        if lock_ok(&self.state.usage).is_some() { self.connect_worker()?; }
        if self.state.ready() { self.state.events.notify(); }
        Ok(())
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        self.state.pause();
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        Ok(FIELD_COUNT)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        allocate_field_descriptor(dwindex)
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> windows::core::Result<()> {
        if pdwcount.is_null() || pdwdefault.is_null() || pbautologonwithdefault.is_null() {
            return Err(E_INVALIDARG.into());
        }
        unsafe {
            let has_signal = self.state.ready();
            let usage = *lock_ok(&self.state.usage);
            let is_logon_ui = matches!(usage, Some(CPUS_LOGON) | Some(CPUS_UNLOCK_WORKSTATION));
            // 新方案（官方示例）：LogonId 留零由 Winlogon 填充，无需"解锁上下文"门槛。
            // 安全性由守护存在性保证：守护只在用户会话运行，开机首屏登录时无信号。
            let not_submitted = !self.state.submitted.load(Ordering::Acquire);
            if has_signal && is_logon_ui && not_submitted {
                *pdwcount = 1;
                *pdwdefault = 0;
                // 守护只有检测到锁屏后的屏幕点亮/开盖唤醒才会送达 signal，
                // 因此这里无需等待鼠标或键盘输入，可以立即提交。
                *pbautologonwithdefault = BOOL(1);
                tracing::info!("[COUNT] 睡眠/开盖唤醒门槛已满足，返回磁贴并自动提交");
            } else {
                *pdwcount = 0;
                *pdwdefault = u32::MAX; // CREDENTIAL_PROVIDER_NO_DEFAULT
                *pbautologonwithdefault = BOOL(0);
                tracing::info!(
                    "[COUNT] 返回 0（signal={} logon_ui={} submitted={}）",
                    has_signal,
                    is_logon_ui,
                    !not_submitted
                );
            }
        }
        Ok(())
    }

    fn GetCredentialAt(
        &self,
        dwindex: u32,
    ) -> windows::core::Result<ICredentialProviderCredential> {
        tracing::info!("[COUNT] GetCredentialAt 被调用");
        if dwindex != 0 || !self.state.ready() {
            return Err(E_INVALIDARG.into());
        }
        let mut result = std::ptr::null_mut();
        unsafe {
            <WatchUnlockProvider_Impl as IUnknownImpl>::QueryInterface(
                self,
                &ICredentialProviderCredential::IID,
                &mut result,
            )
            .ok()?;
            Type::from_abi(result)
        }
    }
}

// ---------- ICredentialProviderCredential_Impl ----------

impl ICredentialProviderCredential_Impl for WatchUnlockProvider_Impl {
    fn Advise(
        &self,
        _pcpce: Option<&ICredentialProviderCredentialEvents>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn UnAdvise(&self) -> windows::core::Result<()> {
        Ok(())
    }
    fn SetSelected(&self) -> windows::core::Result<BOOL> {
        let ready = self.state.ready();
        tracing::info!("[TILE] Watch Unlock 被选择，ready={ready}");
        Ok(BOOL::from(ready))
    }
    fn SetDeselected(&self) -> windows::core::Result<()> {
        Ok(())
    }
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        if pcpfs.is_null() || pcpfis.is_null() {
            return Err(E_INVALIDARG.into());
        }
        let state = match dwfieldid {
            FIELD_PROVIDER_LABEL => CPFS_HIDDEN,
            FIELD_TILE_TITLE => CPFS_DISPLAY_IN_BOTH,
            _ => return Err(E_INVALIDARG.into()),
        };
        unsafe {
            *pcpfs = state;
            *pcpfis = CPFIS_NONE;
        }
        Ok(())
    }
    fn GetStringValue(&self, dwfieldid: u32) -> windows::core::Result<PWSTR> {
        field_text(dwfieldid)
    }
    fn GetBitmapValue(&self, _dwfieldid: u32) -> windows::core::Result<HBITMAP> {
        Err(E_NOTIMPL.into())
    }
    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn GetSubmitButtonValue(&self, _dwfieldid: u32) -> windows::core::Result<u32> {
        Err(E_NOTIMPL.into())
    }
    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows::core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }
    fn SetStringValue(&self, _dwfieldid: u32, _psz: &PCWSTR) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        tracing::info!("[COUNT] GetSerialization 被调用");
        if pcpgsr.is_null() || pcpcs.is_null() {
            return Err(E_INVALIDARG.into());
        }
        unsafe {
            *pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
            *pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE(0);
        }
        let mut sig = self.state.claim_submission()?;
        let usage = *lock_ok(&self.state.usage);
        let message_type = match usage {
            Some(CPUS_LOGON) => KerbInteractiveLogon,
            Some(CPUS_UNLOCK_WORKSTATION) => KerbWorkstationUnlockLogon,
            _ => return Err(E_FAIL.into()),
        };
        let domain = sig.domain.clone();
        let protected_result = protect_password(&sig.password);
        clear_secret(&mut sig.password);
        let protected_password = secret::Text(protected_result?);
        // 先查询认证包，避免后续失败时遗失已经分配的序列化缓冲区。
        let auth_package = retrieve_negotiate_auth_package()?;
        let (raw, size) =
            build_unlock_serialization(&sig.username, &protected_password, &domain, message_type)?;
        unsafe {
            (*pcpcs).ulAuthenticationPackage = auth_package;
            (*pcpcs).clsidCredentialProvider = CLSID;
            (*pcpcs).cbSerialization = size;
            (*pcpcs).rgbSerialization = raw;
            (*pcpgsr).0 = CPGSR_RETURN_CREDENTIAL_FINISHED.0;
        }
        tracing::info!("[PROVIDER] GetSerialization：已返回解锁凭据");
        Ok(())
    }
    fn ReportResult(
        &self,
        ntsstatus: NTSTATUS,
        _ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        tracing::info!("[PROVIDER] ReportResult: {ntsstatus:?}");
        // 一次性语义：无论成败都清除信号，避免失败后无限重试自动提交
        self.state.submitted.store(true, Ordering::Release);
        lock_ok(&self.state.signal).take();
        Ok(())
    }
}

// ---------- 类工厂 + DLL 导出 ----------

#[implement(IClassFactory)]
struct WatchUnlockFactory;

impl IClassFactory_Impl for WatchUnlockFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Option<&IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> windows::core::Result<()> {
        if riid.is_null() || ppvobject.is_null() { return Err(E_INVALIDARG.into()); }
        unsafe { *ppvobject = std::ptr::null_mut(); }
        if punkouter.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let obj: ComObject<WatchUnlockProvider> = ComObject::new(WatchUnlockProvider::new());
        let unknown: IUnknown = obj.to_interface();
        unsafe { unknown.query(riid, ppvobject) }.ok()
    }

    fn LockServer(&self, _flock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

/// LogonUI 通过此入口加载组件。
///
/// # Safety
///
/// `rclsid`、`riid` 和 `ppv` 必须是调用方提供的有效 COM ABI 指针；函数会先检查空指针。
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> windows::core::HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_INVALIDARG;
    }
    *ppv = std::ptr::null_mut();
    if *rclsid != CLSID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: ComObject<WatchUnlockFactory> = ComObject::new(WatchUnlockFactory);
    let unknown: IUnknown = factory.to_interface();
    unknown.query(riid, ppv)
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> windows::core::HRESULT {
    // LogonUI 生命周期内保持加载，避免后台管道线程仍在运行时 DLL 被卸载。
    windows::core::HRESULT(1) // S_FALSE
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authentication::Identity::KERB_LOGON_SUBMIT_TYPE;

    #[test]
    fn concurrent_submission_is_consumed_exactly_once() {
        let provider = WatchUnlockProvider::new();
        *lock_ok(&provider.state.signal) = Some(pipe::UnlockSignal {
            password: "test-only".into(), username: "test".into(), domain: "test".into(),
        });
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let workers: Vec<_> = (0..8).map(|_| {
            let state = provider.state.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                state.claim_submission().is_ok()
            })
        }).collect();
        barrier.wait();
        let accepted = workers.into_iter().filter_map(|worker| worker.join().unwrap().then_some(())).count();
        assert_eq!(accepted, 1);
        assert!(!provider.state.ready());
        assert!(provider.state.claim_submission().is_err());
    }

    #[test]
    fn cancellation_erases_pending_submission() {
        let provider = WatchUnlockProvider::new();
        *lock_ok(&provider.state.signal) = Some(pipe::UnlockSignal {
            password: "test-only".into(), username: "test".into(), domain: "test".into(),
        });
        provider.state.cancel();
        assert!(lock_ok(&provider.state.signal).is_none());
        assert!(!provider.state.ready());
        assert!(provider.state.claim_submission().is_err());
    }

    #[test]
    fn unadvise_pauses_without_retiring_the_provider() {
        let provider = WatchUnlockProvider::new();
        let link = Arc::new(AtomicBool::new(false));
        *lock_ok(&provider.state.link) = link.clone();
        *lock_ok(&provider.state.signal) = Some(pipe::UnlockSignal {
            password: "test-only".into(), username: "test".into(), domain: "test".into(),
        });
        provider.state.pause();
        assert!(link.load(Ordering::Acquire));
        assert!(lock_ok(&provider.state.signal).is_none());
        assert!(!provider.state.stop.load(Ordering::Acquire));
        provider.state.cancel();
        assert!(provider.state.stop.load(Ordering::Acquire));
        assert!(provider.connect_worker().is_err());
    }

    #[test]
    fn unlock_serialization_layout() {
        let (raw, size) =
            build_unlock_serialization("FengXi", "secret", "FENGXIROG", KerbWorkstationUnlockLogon)
                .unwrap();
        let header = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
        assert_eq!(size as usize, header + 18 + 12 + 12);
        unsafe {
            let k = &*(raw as *const KERB_INTERACTIVE_UNLOCK_LOGON);
            assert_eq!(k.Logon.MessageType, KERB_LOGON_SUBMIT_TYPE(7)); // KerbWorkstationUnlockLogon
            assert_eq!(k.LogonId.LowPart, 0);
            assert_eq!(k.LogonId.HighPart, 0);
            // 用户名 "FengXi" = 6 字符 = 12 字节
            assert_eq!(k.Logon.UserName.Length, 12);
            assert_eq!(k.Logon.Password.Length, 12);
            let read = |value: &LSA_UNICODE_STRING| {
                let offset = value.Buffer.0 as usize;
                assert!(offset >= header);
                assert!(offset + value.Length as usize <= size as usize);
                let units = std::slice::from_raw_parts(
                    raw.add(offset) as *const u16,
                    (value.Length / 2) as usize,
                );
                String::from_utf16_lossy(units)
            };
            assert_eq!(read(&k.Logon.LogonDomainName), "FENGXIROG");
            assert_eq!(read(&k.Logon.UserName), "FengXi");
            assert_eq!(read(&k.Logon.Password), "secret");
            windows::Win32::System::Com::CoTaskMemFree(Some(raw as *const core::ffi::c_void));
        }
    }

    #[test]
    fn negotiate_package_is_resolved() {
        // 包编号可能合法地为 0；关键是必须由 LSA 查询，而不是假定固定值。
        let first = retrieve_negotiate_auth_package().unwrap();
        let second = retrieve_negotiate_auth_package().unwrap();
        assert_eq!(first, second);
    }
}
