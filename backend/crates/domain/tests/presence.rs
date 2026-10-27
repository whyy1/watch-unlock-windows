use watch_unlock_domain::{Decision, DevicePolicy, DeviceState, Observation, Presence, Session};

const POLICY: DevicePolicy = DevicePolicy {
    near_rssi: -60,
    far_rssi: -80,
};

fn step(state: &DeviceState, generation: u64, rssi: i16, at_ms: u64) -> watch_unlock_domain::Transition {
    state.step(&POLICY, Session { generation, locked: true }, Observation::Signal { rssi, at_ms }).unwrap()
}

#[test]
fn locking_with_nearby_watch_never_unlocks() {
    let first = step(&DeviceState::default(), 1, -40, 1);
    assert_eq!(first.decision, Decision::None);
    assert!(!first.state.armed());
    assert_eq!(first.state.presence(), Presence::Near);
    assert_eq!(step(&first.state, 1, -40, 2).decision, Decision::None);
}

#[test]
fn a_single_real_far_sample_then_first_near_sample_unlocks() {
    let far = step(&DeviceState::default(), 1, -80, 1);
    assert!(far.state.armed());
    let middle = step(&far.state, 1, -70, 2);
    assert_eq!(middle.state.presence(), Presence::Away);
    assert!(middle.state.armed());
    let near = step(&middle.state, 1, -60, 3);
    assert_eq!(near.decision, Decision::ReturnUnlock);
    assert_eq!(step(&near.state, 1, -40, 4).decision, Decision::None);
}

#[test]
fn another_lock_generation_revokes_previous_distance() {
    let far = step(&DeviceState::default(), 1, -90, 1);
    let near = step(&far.state, 2, -40, 2);
    assert_eq!(near.decision, Decision::None);
    assert!(!near.state.armed());
}

#[test]
fn explicit_adapter_failure_suspend_and_wake_never_authorize() {
    for event in [
        Observation::Unavailable { at_ms: 2 },
        Observation::Suspended { at_ms: 2 },
        Observation::Wake { at_ms: 2 },
    ] {
        let far = step(&DeviceState::default(), 1, -90, 1);
        let revoked = far.state.step(&POLICY, Session { generation: 1, locked: true }, event).unwrap();
        assert_eq!(revoked.decision, Decision::None);
        assert!(!revoked.state.armed());
        assert_eq!(step(&revoked.state, 1, -40, 3).decision, Decision::None);
    }
}

#[test]
fn long_ordinary_device_silence_retains_actual_far_evidence() {
    let far = step(&DeviceState::default(), 1, -90, 1);
    assert_eq!(step(&far.state, 1, -40, 60 * 60 * 1000).decision, Decision::ReturnUnlock);
    assert_eq!(step(&DeviceState::default(), 1, -40, 60 * 60 * 1000).decision, Decision::None);
}

#[test]
fn an_expired_return_needs_a_new_far_crossing() {
    let far = step(&DeviceState::default(), 1, -90, 1);
    let returned = step(&far.state, 1, -40, 2);
    assert_eq!(returned.decision, Decision::ReturnUnlock);
    let expired = returned.state.expire_unsubmitted_return();
    assert!(!expired.armed());
    assert_eq!(step(&expired, 1, -40, 3).decision, Decision::None);
    let again_far = step(&expired, 1, -90, 4);
    assert!(again_far.state.armed());
    assert_eq!(step(&again_far.state, 1, -40, 5).decision, Decision::ReturnUnlock);
}

#[test]
fn a_consumed_return_does_not_rearm_within_the_same_lock() {
    let far = step(&DeviceState::default(), 1, -90, 1);
    let returned = step(&far.state, 1, -40, 2);
    let again_far = step(&returned.state, 1, -90, 3);
    assert!(!again_far.state.armed());
    assert_eq!(step(&again_far.state, 1, -40, 4).decision, Decision::None);
}

#[test]
fn restart_does_not_recover_authority_and_devices_are_isolated() {
    let first_watch = step(&DeviceState::default(), 1, -90, 1);
    assert!(first_watch.state.armed());
    let second_watch = step(&DeviceState::default(), 1, -40, 2);
    assert_eq!(second_watch.decision, Decision::None);
    let restarted = step(&DeviceState::default(), 1, -40, 3);
    assert_eq!(restarted.decision, Decision::None);
}

#[test]
fn unlocked_session_never_requests_unlock_and_clears_authority() {
    let far = step(&DeviceState::default(), 1, -90, 1);
    let unlocked = far.state.step(
        &POLICY, Session { generation: 1, locked: false }, Observation::Signal { rssi: -40, at_ms: 2 },
    ).unwrap();
    assert_eq!(unlocked.decision, Decision::None);
    assert!(!unlocked.state.armed());
    assert_eq!(unlocked.state.presence(), Presence::Unknown);
}

#[test]
fn invalid_inputs_leave_original_state_unchanged() {
    let state = step(&DeviceState::default(), 2, -90, 10).state;
    for (policy, session, event) in [
        (POLICY, Session { generation: 2, locked: true }, Observation::Signal { rssi: 127, at_ms: 11 }),
        (POLICY, Session { generation: 2, locked: true }, Observation::Signal { rssi: -40, at_ms: 9 }),
        (POLICY, Session { generation: 1, locked: true }, Observation::Signal { rssi: -40, at_ms: 11 }),
        (DevicePolicy { far_rssi: -60, ..POLICY }, Session { generation: 2, locked: true }, Observation::Wake { at_ms: 11 }),
    ] {
        assert!(state.step(&policy, session, event).is_err());
        assert!(state.armed());
    }
}

#[test]
fn departure_before_the_lock_arms_only_a_fresh_locked_cycle() {
    let locked = DeviceState::default()
        .step(&POLICY, Session { generation: 2, locked: true }, Observation::Unavailable { at_ms: 1 })
        .unwrap();
    let armed = locked.state.arm_departed();
    assert!(armed.armed());
    assert_eq!(armed.presence(), Presence::Away);
    assert_eq!(step(&armed, 2, -60, 2).decision, Decision::ReturnUnlock);

    let unlocked = DeviceState::default()
        .step(&POLICY, Session { generation: 1, locked: false }, Observation::Unavailable { at_ms: 1 })
        .unwrap();
    assert!(!unlocked.state.arm_departed().armed());

    let returned = step(&armed, 2, -60, 2).state;
    assert!(!returned.arm_departed().armed());
}
