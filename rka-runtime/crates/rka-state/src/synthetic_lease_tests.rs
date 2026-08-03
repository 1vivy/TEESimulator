use super::*;

fn bundle(epoch: u64, marker: u8, now: u64) -> SyntheticLeaseBundle {
    SyntheticLeaseBundle::new(
        epoch,
        [1; 32],
        [2; 32],
        now.saturating_sub(300_000),
        now.saturating_add(3_600_000),
        vec![marker; 121],
        vec![0x30, marker, 0x01],
        vec![vec![0x30, marker], vec![0x30, marker.saturating_add(1)]],
        now,
    )
    .unwrap()
}

#[test]
fn current_next_promotion_round_trips_as_one_record() {
    let now = 1_800_000_000_000;
    let mut state = SyntheticLeaseState::empty();
    assert_eq!(
        state.install(bundle(0, 3, now)),
        Ok(SyntheticLeaseInstall::Current)
    );
    let current_id = *state.current().unwrap().lease_id();
    assert_eq!(
        state.install(bundle(1, 4, now)),
        Ok(SyntheticLeaseInstall::Next)
    );
    let next_id = *state.next().unwrap().lease_id();
    let encoded = state.encode().unwrap();
    let mut reopened = SyntheticLeaseState::decode(&encoded, now).unwrap();

    assert_eq!(reopened.current().unwrap().lease_id(), &current_id);
    assert_eq!(reopened.next().unwrap().lease_id(), &next_id);
    reopened.promote().unwrap();
    assert_eq!(reopened.current().unwrap().lease_id(), &next_id);
    assert!(reopened.next().is_none());
}

#[test]
fn tamper_expiry_replay_downgrade_and_gap_fail_closed() {
    let now = 1_800_000_000_000;
    let mut state = SyntheticLeaseState::empty();
    state.install(bundle(0, 3, now)).unwrap();
    let mut encoded = state.encode().unwrap();
    let last = encoded.len().saturating_sub(1);
    *encoded.get_mut(last).unwrap() ^= 1;
    assert!(matches!(
        SyntheticLeaseState::decode(&encoded, now),
        Err(SyntheticLeaseError::Tampered)
    ));
    assert!(matches!(
        SyntheticLeaseState::decode(&state.encode().unwrap(), now.saturating_add(3_600_000)),
        Err(SyntheticLeaseError::Expired)
    ));
    assert_eq!(
        state.install(bundle(0, 9, now)),
        Err(SyntheticLeaseError::Replay)
    );
    assert_eq!(
        state.install(bundle(2, 5, now)),
        Err(SyntheticLeaseError::EpochGap)
    );
    state.install(bundle(1, 4, now)).unwrap();
    state.promote().unwrap();
    assert_eq!(
        state.install(bundle(0, 3, now)),
        Err(SyntheticLeaseError::Downgrade)
    );
}

#[test]
fn debug_never_contains_private_material() {
    let now = 1_800_000_000_000;
    let private_marker = "7777777777777777";
    let value = bundle(0, 0x77, now);
    let debug = format!("{value:?}");

    assert!(!debug.contains(private_marker));
    assert!(debug.contains("redacted"));
}
