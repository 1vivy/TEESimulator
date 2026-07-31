#![allow(missing_docs, reason = "integration tests are behavior-named")]

#[path = "donor_rka/support.rs"]
mod donor_rka_support;

use donor_rka_support::{FakeBroker, Fixture};
use rka_sidecar::donor::{DonorError, DonorKeyState, DonorRkaService};

#[test]
fn donor_generate_operate_delete() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());

    // When
    let generated = donor.generate(fixture.generate(1), &mut broker)?;
    let first = donor.begin(fixture.begin(2), &mut broker)?;
    donor.abort(fixture.abort(3, first.operation_handle), &mut broker)?;
    let second = donor.begin(fixture.begin(4), &mut broker)?;
    donor.update(
        fixture.update(5, second.operation_handle, b"message"),
        &mut broker,
    )?;
    let finished = donor.finish(fixture.finish(6, second.operation_handle), &mut broker)?;
    let deleted = donor.delete(fixture.delete(7), &mut broker)?;

    // Then
    assert_eq!(generated.state, DonorKeyState::Active);
    assert!(!finished.signature.is_empty());
    assert_eq!(finished.successful_finish_count, 1);
    assert_eq!(deleted, DonorKeyState::Deleted);
    assert_eq!(broker.abort_calls, 1);
    assert_eq!(broker.finish_calls, 1);
    assert_eq!(broker.delete_calls, 1);
    Ok(())
}

#[test]
fn donor_rejects_identity_drift() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;

    // When
    let rejected = donor.begin(fixture.begin_with_identity(2, [0x99; 32]), &mut broker);

    // Then
    assert_eq!(rejected, Err(DonorError::IdentityDrift));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(broker.delete_calls, 1);
    Ok(())
}

#[test]
fn donor_rejects_replay() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;

    // When
    let replayed = donor.get(fixture.get(1));

    // Then
    assert_eq!(replayed, Err(DonorError::Replay));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(broker.generated_requests, 1);
    Ok(())
}

#[test]
fn donor_rka_rejects_policy_epoch_nonce_ttl_and_pair_mismatch() {
    // Given
    let fixture = Fixture::new();

    // When
    let stale = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_epoch(1, 8),
        &mut FakeBroker::default(),
    );
    let expired = DonorRkaService::new(fixture.policy())
        .generate(fixture.generate_at(1, 120_001), &mut FakeBroker::default());
    let peer = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_peer(1, [0x44; 32]),
        &mut FakeBroker::default(),
    );
    let nonce = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_nonce(1, [0x55; 32]),
        &mut FakeBroker::default(),
    );

    // Then
    assert_eq!(stale, Err(DonorError::StaleProfile));
    assert_eq!(expired, Err(DonorError::Expired));
    assert_eq!(peer, Err(DonorError::Unpaired));
    assert_eq!(nonce, Err(DonorError::EnvelopeMismatch));
}

#[test]
fn donor_rka_rejects_envelope_leak_or_broken_hash_binding() {
    // Given
    let fixture = Fixture::new();

    // When
    let leaked = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_upstream_envelope(1),
        &mut FakeBroker::default(),
    );
    let broken = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_broken_csr_hash(1),
        &mut FakeBroker::default(),
    );

    // Then
    assert_eq!(leaked, Err(DonorError::EnvelopeUpstream));
    assert_eq!(broken, Err(DonorError::EnvelopeMismatch));
}

#[test]
fn donor_rka_serializes_same_handle_and_counts_only_successful_finish()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    let first = donor.begin(fixture.begin(2), &mut broker)?;

    // When
    let concurrent = donor.begin(fixture.begin(3), &mut broker);
    donor.abort(fixture.abort(4, first.operation_handle), &mut broker)?;
    let fresh = donor.begin(fixture.begin(5), &mut broker)?;
    donor.finish(fixture.finish(6, fresh.operation_handle), &mut broker)?;
    let exhausted = donor.begin(fixture.begin(7), &mut broker);

    // Then
    assert_eq!(concurrent, Err(DonorError::ConcurrentOperation));
    assert_eq!(exhausted, Err(DonorError::UseLimit));
    assert_eq!(broker.finish_calls, 1);
    Ok(())
}

#[test]
fn donor_rka_peer_death_and_policy_failure_are_terminal() -> Result<(), Box<dyn std::error::Error>>
{
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    let operation = donor.begin(fixture.begin(2), &mut broker)?;

    // When
    donor.peer_died(&mut broker);
    let after_death = donor.update(
        fixture.update(3, operation.operation_handle, b"x"),
        &mut broker,
    );

    // Then
    assert_eq!(after_death, Err(DonorError::Quarantined));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(broker.abort_calls, 1);
    assert_eq!(broker.delete_calls, 1);
    Ok(())
}
