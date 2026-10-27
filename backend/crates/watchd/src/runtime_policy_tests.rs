use super::*;

const POLICY: DevicePolicy = DevicePolicy {
    near_rssi: -60,
    far_rssi: -80,
};
const LOCKED: Session = Session { generation: 1, locked: true };

fn observe(device: &DeviceAuthority, origin: Instant, milliseconds: u64, rssi: i16) -> SignalTransition {
    device.observe(LOCKED, rssi, origin + Duration::from_millis(milliseconds), milliseconds).unwrap()
}

fn ready() -> SubmissionConditions {
    SubmissionConditions { locked: true, provider_ready: true, verified_locked: true,
        credential_configured: true, scanner_running: true }
}

fn at(origin: Instant, milliseconds: u64) -> Instant { origin + Duration::from_millis(milliseconds) }

#[test]
fn nearby_lock_and_repeated_display_wakes_never_create_authority() {
    let origin = Instant::now();
    let initial = observe(&DeviceAuthority::new(POLICY), origin, 0, -40);
    assert_eq!(initial.decision, Decision::None);
    // A display wake keeps a healthy scanner, but contributes no signal or authority.
    let next = observe(&initial.authority, origin, 1000, -40);
    let (_, submit) = SubmissionGate::default().reserve(ready(), next.authority.authorized(at(origin, 1000)));
    assert!(!submit);
    assert!(!next.authority.armed());
    assert_eq!(next.decision, Decision::None);
}

#[test]
fn real_far_then_first_near_after_hours_of_healthy_silence_can_submit_once() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 1, -80);
    assert!(far.crossed_far);
    assert!(far.authority.rssi(origin + Duration::from_secs(3600)).is_none());
    let returned = observe(&far.authority, origin, 3_600_001, -60);
    assert_eq!(returned.decision, Decision::ReturnUnlock);
    let (reserved, submit) = SubmissionGate::default().reserve(ready(), returned.authority.authorized(at(origin, 3_600_001)));
    assert!(submit);
    // Reserving before IPC means a failed send, another device or a config reload
    // cannot create a second attempt in the same Windows lock cycle.
    let (again, duplicate) = reserved.reserve(ready(), true);
    assert!(!duplicate);
    assert!(again.submitted());
}

#[test]
fn lock_floor_discards_queued_prelock_far_and_adapter_failure_rejects_queue() {
    let origin = Instant::now();
    let floor = origin + Duration::from_millis(100);
    assert!(!accepts_signal(origin, floor, floor, true));
    assert!(!accepts_signal(floor, floor, floor, false));
    assert!(accepts_signal(floor, floor, floor, true));
    assert!(!accepts_signal(floor, floor + SIGNAL_FRESH + Duration::from_millis(1), floor, true));
    assert!(!accepts_signal(floor + Duration::from_millis(1), floor, floor, true));
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 101, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 101)));
}

#[test]
fn failed_scanner_suspend_restart_and_relock_revoke_observed_far() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    for revoked in [
        far.authority.invalidate(LOCKED, 1).unwrap(),
        DeviceAuthority::new(POLICY),
        far.authority.invalidate(Session { generation: 2, locked: true }, 1).unwrap(),
    ] {
        let generation = revoked.state.generation().max(1);
        let next = revoked.observe(Session { generation, locked: true }, -40, at(origin, 2), 2).unwrap();
        assert_eq!(next.decision, Decision::None);
        assert!(!next.authority.authorized(at(origin, 2)));
    }
    // If the scanner dies after signal evaluation, the final side-effect gate
    // still rejects the otherwise-valid arrival until invalidation is processed.
    let returned = observe(&far.authority, origin, 1, -40);
    let (_, submit) = SubmissionGate::default().reserve(SubmissionConditions { scanner_running: false, ..ready() },
        returned.authority.authorized(at(origin, 1)));
    assert!(!submit);
}

#[test]
fn out_of_order_callbacks_cannot_invent_a_far_return_after_a_newer_near() {
    let origin = Instant::now();
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 20, -40);
    let delayed_far = observe(&nearby.authority, origin, 10, -90);
    assert!(!delayed_far.crossed_far);
    assert!(!delayed_far.authority.armed());
    let later = observe(&delayed_far.authority, origin, 21, -40);
    assert!(!later.authority.authorized(at(origin, 21)));
}

#[test]
fn different_devices_keep_thresholds_and_evidence_separate() {
    let origin = Instant::now();
    let first = observe(&DeviceAuthority::new(POLICY), origin, 0, -85);
    let strict_policy = DevicePolicy { near_rssi: -35, far_rssi: -95 };
    let second = observe(&DeviceAuthority::new(strict_policy), origin, 1, -85);
    assert!(first.authority.armed());
    assert!(!second.authority.armed());
    let first_return = observe(&first.authority, origin, 2, -50);
    let second_middle = observe(&second.authority, origin, 2, -50);
    assert!(first_return.authority.authorized(at(origin, 2)));
    assert!(!second_middle.authority.authorized(at(origin, 2)));
    let second_near = observe(&second_middle.authority, origin, 3, -30);
    assert_eq!(second_near.decision, Decision::None);
    assert!(!second_near.authority.authorized(at(origin, 3)));
}

#[test]
fn expired_unsubmitted_arrival_needs_a_fresh_far_crossing() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    let (_, submit) = SubmissionGate::default().reserve(SubmissionConditions { provider_ready: false, ..ready() },
        returned.authority.authorized(at(origin, 1)));
    assert!(!submit);
    let (expired, did_expire) = returned.authority.expire_return(at(origin, 2002));
    assert!(did_expire);
    assert!(!expired.armed());
    let nearby = observe(&expired, origin, 2003, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 2003)));
    let fresh_far = observe(&nearby.authority, origin, 2004, -90);
    assert!(fresh_far.crossed_far);
    let fresh_return = observe(&fresh_far.authority, origin, 2005, -40);
    assert!(fresh_return.authority.authorized(at(origin, 2005)));
}

#[test]
fn scanner_failure_after_arrival_before_submission_allows_secure_retry() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    let failed = returned.authority.invalidate(LOCKED, 2).unwrap();
    let nearby = observe(&failed, origin, 3, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 3)));
    let fresh_far = observe(&nearby.authority, origin, 4, -90);
    assert!(fresh_far.crossed_far);
    // A consumed submission is distinct from a failed/unsubmitted arrival.
    let consumed = returned.authority.consume_submission().invalidate(LOCKED, 2).unwrap();
    let after_submission = observe(&consumed, origin, 3, -40);
    assert_eq!(after_submission.decision, Decision::None);
    assert!(!after_submission.authority.authorized(at(origin, 3)));
}

#[test]
fn every_platform_precondition_fails_closed_before_ipc_is_reserved() {
    for unavailable in [
        SubmissionConditions { locked: false, ..ready() },
        SubmissionConditions { provider_ready: false, ..ready() },
        SubmissionConditions { verified_locked: false, ..ready() },
        SubmissionConditions { credential_configured: false, ..ready() },
        SubmissionConditions { scanner_running: false, ..ready() },
    ] {
        let (gate, submit) = SubmissionGate::default().reserve(unavailable, true);
        assert!(!submit);
        assert!(!gate.submitted());
    }
    let (_, no_authority) = SubmissionGate::default().reserve(ready(), false);
    assert!(!no_authority);
}

#[test]
fn ipc_grant_uses_the_earlier_of_signal_freshness_and_return_window() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let arrived = observe(&far.authority, origin, 1, -40);
    let later_near = observe(&arrived.authority, origin, 1000, -40);
    // Default window equals signal freshness: the return at 1 ms bounds it.
    assert_eq!(later_near.authority.authorization_deadline(at(origin, 1000)), Some(at(origin, 2001)));
    let windowed = observe(&far.authority.with_return_window(Duration::from_secs(30)), origin, 1, -40);
    let later = observe(&windowed.authority, origin, 1000, -40);
    assert_eq!(later.authority.authorization_deadline(at(origin, 1000)), Some(at(origin, 1000) + SIGNAL_FRESH));
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 0, -40);
    assert!(nearby.authority.authorization_deadline(origin).is_none());
}

#[test]
fn return_waits_for_the_logon_ui_within_the_configured_window() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30));
    let far = observe(&device, origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    // The logon UI connects 10 s later while the watch keeps advertising nearby.
    let (kept, expired) = returned.authority.expire_return(origin + Duration::from_secs(10));
    assert!(!expired);
    let still_near = observe(&kept, origin, 10_000, -45);
    assert!(still_near.authority.authorized(origin + Duration::from_secs(10)));
    // Seamless: the window counts from the return, however long the watch stays near.
    let (_, gone) = still_near.authority.expire_return(at(origin, 30_002));
    assert!(gone);
}

#[test]
fn held_return_waits_for_input_while_the_watch_stays_near() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30)).with_hold_while_near(true);
    let far = observe(&device, origin, 0, -90);
    let mut current = observe(&far.authority, origin, 1, -40).authority;
    // The user sits down and only touches the mouse two minutes later.
    for second in 1..=120u64 {
        current = observe(&current, origin, second * 1000, -45).authority;
        let (kept, expired) = current.expire_return(at(origin, second * 1000));
        assert!(!expired);
        current = kept;
    }
    assert!(current.authorized(at(origin, 120_000)));
    // Out of range for longer than the window ends it.
    let (_, gone) = current.expire_return(at(origin, 150_001));
    assert!(gone);
    // Crossing the far threshold again also ends it; only a new return authorizes.
    let left = observe(&current, origin, 121_000, -90);
    assert!(left.crossed_far);
    assert!(!left.authority.authorized(at(origin, 121_000)));
}

#[test]
fn input_must_follow_the_return_tick_even_across_wraparound() {
    assert!(!input_after(None, 100));
    assert!(!input_after(Some(100), 100));
    assert!(!input_after(Some(99), 100));
    assert!(input_after(Some(101), 100));
    assert!(input_after(Some(5), u32::MAX - 5));
}

#[test]
fn a_kept_return_needs_a_fresh_near_signal_and_ends_when_leaving_again() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30));
    let far = observe(&device, origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    // No advertisement for 10 s: the return is kept but cannot submit on stale distance.
    assert!(!returned.authority.authorized(origin + Duration::from_secs(10)));
    let left = observe(&returned.authority, origin, 5_000, -90);
    assert!(left.crossed_far);
    // Leaving discards the pending return, so nothing remains to expire.
    assert!(!left.authority.expire_return(origin + Duration::from_secs(60)).1);
    // Coming back again is a new return with its own window.
    let back = observe(&left.authority, origin, 6_000, -40);
    assert_eq!(back.decision, Decision::ReturnUnlock);
    assert!(back.authority.authorized(at(origin, 6_000)));
}

const UNLOCKED: Session = Session { generation: 1, locked: false };
const RELOCKED: Session = Session { generation: 2, locked: true };

fn before_lock(device: &DeviceAuthority, origin: Instant, milliseconds: u64, rssi: i16) -> DeviceAuthority {
    device.observe(UNLOCKED, rssi, at(origin, milliseconds), milliseconds).unwrap().authority
}

/// What the daemon does on a new lock: snapshot, revoke, then carry a departure across.
fn lock(device: &DeviceAuthority, trusted: bool, milliseconds: u64) -> DeviceAuthority {
    let departed = device.departed();
    let locked = device.invalidate(RELOCKED, milliseconds).unwrap();
    if departed && trusted { locked.arm_departed() } else { locked }
}

#[test]
fn dynamic_lock_after_the_watch_left_unlocks_on_the_first_return() {
    let origin = Instant::now();
    let left = before_lock(&DeviceAuthority::new(POLICY), origin, 0, -85);
    assert!(left.departed());
    // Dynamic Lock locks about a minute later; no signal arrives while the watch is gone.
    let locked = lock(&left, true, 60_000);
    assert!(locked.armed());
    let returned = locked.observe(RELOCKED, -55, at(origin, 600_000), 600_000).unwrap();
    assert_eq!(returned.decision, Decision::ReturnUnlock);
    assert!(returned.authority.authorized(at(origin, 600_000)));
}

#[test]
fn locking_beside_the_pc_never_arms_from_earlier_departures() {
    let origin = Instant::now();
    let left = before_lock(&DeviceAuthority::new(POLICY), origin, 0, -85);
    let back = before_lock(&left, origin, 1_000, -70);
    assert!(!back.departed());
    let locked = lock(&back, true, 2_000);
    assert!(!locked.armed());
    let near = locked.observe(RELOCKED, -50, at(origin, 3_000), 3_000).unwrap();
    assert_eq!(near.decision, Decision::None);

    let nearby = lock(&before_lock(&DeviceAuthority::new(POLICY), origin, 0, -45), true, 1_000);
    assert!(!nearby.armed());
    assert!(!lock(&DeviceAuthority::new(POLICY), true, 1_000).armed());
}

#[test]
fn a_departure_is_void_when_the_scanner_or_settings_changed_at_the_lock() {
    let origin = Instant::now();
    let left = before_lock(&DeviceAuthority::new(POLICY), origin, 0, -85);
    assert!(!lock(&left, false, 60_000).armed());
    // A revocation before the lock clears the remembered signal itself.
    let revoked = left.invalidate(UNLOCKED, 30_000).unwrap();
    assert!(!revoked.departed());
    assert!(!lock(&revoked, true, 60_000).armed());
}

#[test]
fn lock_cause_prefers_recent_input_then_display_off_then_dynamic_lock() {
    let s = Duration::from_secs;
    assert_eq!(lock_cause(Some(s(1)), Some(s(1)), true), LockCause::Manual);
    assert_eq!(lock_cause(Some(s(3)), None, true), LockCause::Manual);
    assert_eq!(lock_cause(Some(s(4)), Some(s(5)), true), LockCause::DisplayOff);
    assert_eq!(lock_cause(Some(s(4)), Some(s(6)), false), LockCause::Unknown);
    assert_eq!(lock_cause(Some(s(20)), Some(s(60)), true), LockCause::DynamicLock);
    assert_eq!(lock_cause(Some(s(19)), None, true), LockCause::Unknown);
    assert_eq!(lock_cause(Some(s(600)), None, false), LockCause::Unknown);
    assert_eq!(lock_cause(None, None, true), LockCause::Unknown);
}

#[test]
fn blockers_name_each_failed_condition() {
    assert!(ready().blockers().is_empty());
    let waiting = SubmissionConditions { provider_ready: false, credential_configured: false, ..ready() };
    assert_eq!(waiting.blockers(), vec!["登录界面组件未连接", "没有保存账户密码"]);
}

#[test]
fn the_lid_switch_is_off_by_default_and_changes_nothing_while_off() {
    let default: crate::registry::Settings = serde_json::from_str("{}").unwrap();
    assert!(!default.scan_with_lid_closed);
    // Off: closing the lid stops scanning, as in every earlier version.
    assert!(lid_close_stops_scanning(default.scan_with_lid_closed));
    assert!(!lid_close_stops_scanning(true));
    // Saving without flipping it, or flipping it with the lid open, leaves scanning alone.
    for lid_closed in [false, true] {
        assert_eq!(lid_switch_change(lid_closed, false, false), None);
        assert_eq!(lid_switch_change(lid_closed, true, true), None);
    }
    assert_eq!(lid_switch_change(false, false, true), None);
    assert_eq!(lid_switch_change(false, true, false), None);
    // Flipped while the lid is shut: applies at once.
    assert_eq!(lid_switch_change(true, false, true), Some(true));
    assert_eq!(lid_switch_change(true, true, false), Some(false));
}
