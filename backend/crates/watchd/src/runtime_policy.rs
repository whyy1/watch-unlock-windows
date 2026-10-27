//! Side-effect-free arbitration shared by the daemon and its scenario tests.

use std::time::{Duration, Instant};
use watch_unlock_domain::{Decision, DevicePolicy, DeviceState, Observation, PolicyError, Session};

pub(super) const SIGNAL_FRESH: Duration = Duration::from_secs(2);

/// A queue can contain observations from before a lock, suspend or adapter fault.
/// Neither a recent processing time nor a later wake makes those observations new.
pub(super) fn accepts_signal(
    received_at: Instant,
    now: Instant,
    evidence_floor: Instant,
    scanner_running: bool,
) -> bool {
    scanner_running
        && received_at >= evidence_floor
        && received_at <= now
        && now.duration_since(received_at) <= SIGNAL_FRESH
}

/// Whether keyboard or mouse input happened after tick `since`. Tick counts wrap after
/// ~49 days; the signed difference stays correct across the wrap.
pub(super) fn input_after(last_input: Option<u32>, since: u32) -> bool {
    last_input.is_some_and(|last| (last.wrapping_sub(since) as i32) > 0)
}

/// Whether closing the lid stops scanning. With the switch off (the default) it does, exactly
/// as before the switch existed.
pub(super) fn lid_close_stops_scanning(scan_with_lid_closed: bool) -> bool {
    !scan_with_lid_closed
}

/// After a settings reload: the new scan request, or None to leave scanning untouched. Only a
/// switch flipped while the lid is closed changes anything; with the lid open, opening it
/// already resumed scanning.
pub(super) fn lid_switch_change(lid_closed: bool, before: bool, after: bool) -> Option<bool> {
    (lid_closed && before != after).then_some(after)
}

/// Windows does not say why a session locked; this is a best guess for the event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LockCause {
    Manual,
    DisplayOff,
    DynamicLock,
    Unknown,
}

const MANUAL_INPUT: Duration = Duration::from_secs(3);
const DISPLAY_OFF: Duration = Duration::from_secs(5);
/// Dynamic Lock waits for the paired device to be gone for a while, with nobody at the PC.
const DYNAMIC_LOCK_IDLE: Duration = Duration::from_secs(20);

pub(super) fn lock_cause(idle: Option<Duration>, since_display_off: Option<Duration>, dynamic_lock: bool) -> LockCause {
    if idle.is_some_and(|idle| idle <= MANUAL_INPUT) {
        LockCause::Manual
    } else if since_display_off.is_some_and(|since| since <= DISPLAY_OFF) {
        LockCause::DisplayOff
    } else if dynamic_lock && idle.is_some_and(|idle| idle >= DYNAMIC_LOCK_IDLE) {
        LockCause::DynamicLock
    } else {
        LockCause::Unknown
    }
}

impl LockCause {
    pub fn text(self) -> &'static str {
        match self {
            Self::Manual => "主动锁定（Win+L 等）",
            Self::DisplayOff => "熄屏后锁定",
            Self::DynamicLock => "可能是动态锁",
            Self::Unknown => "无操作超时或其他原因",
        }
    }
}

#[derive(Clone)]
pub(super) struct DeviceAuthority {
    policy: DevicePolicy,
    state: DeviceState,
    last_signal: Option<(Instant, i16)>,
    return_at: Option<Instant>,
    /// How long a far-then-near return stays usable while the logon UI appears.
    return_window: Duration,
    /// With seamless unlock off, a return waits for keyboard or mouse input. It stays usable
    /// while the watch keeps advertising nearby, and lapses once it has been out of range for
    /// the return window or crosses the far threshold again.
    hold_while_near: bool,
}

pub(super) struct SignalTransition {
    pub authority: DeviceAuthority,
    pub decision: Decision,
    pub crossed_far: bool,
}

impl DeviceAuthority {
    pub fn new(policy: DevicePolicy) -> Self {
        Self {
            policy,
            state: DeviceState::default(),
            last_signal: None,
            return_at: None,
            return_window: SIGNAL_FRESH,
            hold_while_near: false,
        }
    }

    /// The Credential Provider only connects once the user opens the logon UI, which usually
    /// takes longer than a signal's freshness. Submission still requires a fresh near signal.
    pub fn with_return_window(&self, window: Duration) -> Self {
        Self { return_window: window.max(SIGNAL_FRESH), ..self.clone() }
    }

    pub fn with_hold_while_near(&self, hold: bool) -> Self {
        Self { hold_while_near: hold, ..self.clone() }
    }

    pub fn invalidate(&self, session: Session, at_ms: u64) -> Result<Self, PolicyError> {
        let next = self.state.step(&self.policy, session, Observation::Unavailable { at_ms })?;
        let state = if self.return_at.is_some() { next.state.expire_unsubmitted_return() } else { next.state };
        Ok(Self {
            state,
            last_signal: None,
            return_at: None,
            ..self.clone()
        })
    }

    pub fn with_policy(&self, policy: DevicePolicy) -> Self {
        Self { policy, ..self.clone() }
    }

    pub fn observe(
        &self,
        session: Session,
        rssi: i16,
        received_at: Instant,
        at_ms: u64,
    ) -> Result<SignalTransition, PolicyError> {
        // A delayed callback must not move the device backwards through distance.
        if self.last_signal.is_some_and(|(last, _)| received_at < last) {
            return Ok(SignalTransition { authority: self.clone(), decision: Decision::None, crossed_far: false });
        }
        // Leaving again while a return waits for the logon UI discards that return, so this far
        // signal re-arms and only the next return can authorize.
        let base = if self.return_at.is_some() && rssi <= self.policy.far_rssi {
            Self { state: self.state.expire_unsubmitted_return(), return_at: None, ..self.clone() }
        } else {
            self.clone()
        };
        let next = base.state.step(&base.policy, session, Observation::Signal { rssi, at_ms })?;
        let crossed_far = next.state.armed() && !base.state.armed();
        let return_at = if next.decision == Decision::ReturnUnlock { Some(received_at) } else { base.return_at };
        Ok(SignalTransition {
            authority: Self { state: next.state, last_signal: Some((received_at, rssi)), return_at, ..base },
            decision: next.decision,
            crossed_far,
        })
    }

    pub fn armed(&self) -> bool { self.state.armed() }

    /// The last signal seen from this device, however old. Cleared whenever evidence is revoked.
    pub fn last_signal(&self) -> Option<(Instant, i16)> { self.last_signal }

    /// The last signal before the lock was already past the far threshold, with nothing nearer since.
    pub fn departed(&self) -> bool {
        self.last_signal.is_some_and(|(_, rssi)| rssi <= self.policy.far_rssi)
    }

    /// Call right after the lock's `invalidate`, only when `departed()` held before it.
    pub fn arm_departed(&self) -> Self {
        Self { state: self.state.arm_departed(), ..self.clone() }
    }

    pub fn rssi(&self, now: Instant) -> Option<i16> {
        self.last_signal.filter(|(at, _)| *at <= now && now.duration_since(*at) <= SIGNAL_FRESH).map(|(_, rssi)| rssi)
    }

    pub fn near(&self, now: Instant) -> bool {
        self.rssi(now).is_some_and(|rssi| rssi >= self.policy.near_rssi)
    }

    pub fn consume_submission(&self) -> Self {
        Self { return_at: None, ..self.clone() }
    }

    /// When the return window starts. A held return restarts it at every later near signal.
    fn return_anchor(&self) -> Option<Instant> {
        let at = self.return_at?;
        Some(match self.last_signal {
            Some((seen, rssi)) if self.hold_while_near && seen > at && rssi >= self.policy.near_rssi => seen,
            _ => at,
        })
    }

    pub fn expire_return(&self, now: Instant) -> (Self, bool) {
        if self.return_anchor().is_some_and(|at| now.saturating_duration_since(at) > self.return_window) {
            return (Self { return_at: None, state: self.state.expire_unsubmitted_return(), ..self.clone() }, true);
        }
        (self.clone(), false)
    }

    pub fn authorized(&self, now: Instant) -> bool {
        self.authorization_deadline(now).is_some()
    }

    pub fn authorization_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.near(now) { return None; }
        let signal_until = self.last_signal?.0 + SIGNAL_FRESH;
        let return_until = self.return_anchor().filter(|at| *at <= now)? + self.return_window;
        let deadline = signal_until.min(return_until);
        (now < deadline).then_some(deadline)
    }
}

/// This is reset by an actual new Windows lock, never by scanner/configuration
/// generations. Reserve before sending IPC, including failed sends.
#[derive(Clone, Copy, Default)]
pub(super) struct SubmissionGate { submitted: bool }

#[derive(Clone, Copy)]
pub(super) struct SubmissionConditions {
    pub locked: bool,
    pub provider_ready: bool,
    pub verified_locked: bool,
    pub credential_configured: bool,
    pub scanner_running: bool,
}

impl SubmissionConditions {
    /// Every condition that currently stops an authorized return, in user terms.
    pub fn blockers(&self) -> Vec<&'static str> {
        [
            (!self.locked, "后台认为电脑没有锁屏"),
            (!self.provider_ready, "登录界面组件未连接"),
            (!self.verified_locked, "正在核对锁屏状态或配置"),
            (!self.credential_configured, "没有保存账户密码"),
            (!self.scanner_running, "蓝牙扫描未运行"),
        ].into_iter().filter_map(|(blocked, reason)| blocked.then_some(reason)).collect()
    }
}

impl SubmissionGate {
    pub fn submitted(self) -> bool { self.submitted }

    pub fn reserve(self, conditions: SubmissionConditions, authorized: bool) -> (Self, bool) {
        let submit = !self.submitted && authorized && conditions.locked && conditions.provider_ready
            && conditions.verified_locked && conditions.credential_configured && conditions.scanner_running;
        (Self { submitted: self.submitted || submit }, submit)
    }
}

#[cfg(test)]
#[path = "runtime_policy_tests.rs"]
mod tests;
