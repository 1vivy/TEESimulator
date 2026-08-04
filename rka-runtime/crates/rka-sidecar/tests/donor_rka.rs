#![allow(missing_docs, reason = "integration tests are behavior-named")]
// allow: SIZE_OK — cohesive donor integration suite; W0-T1 requires this exact test file.

#[path = "donor_rka/support.rs"]
mod donor_rka_support;

use donor_rka_support::{FakeBroker, Fixture};
use rka_sidecar::donor::{DonorError, DonorKeyState, DonorRkaService};

#[test]
fn candidate_b_policy_shares_no_identity_material_with_candidate_a() {
    // Given
    let candidate_a = Fixture::new();
    let candidate_b = Fixture::candidate_b();

    // When
    let (peer_a, profile_a, identity_a) = candidate_a.policy_identity_material();
    let (peer_b, profile_b, identity_b) = candidate_b.policy_identity_material();

    // Then
    assert_ne!(peer_a, peer_b);
    assert_ne!(profile_a, profile_b);
    assert_ne!(identity_a, identity_b);
}

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
fn donor_rka_rejects_broken_hash_binding() {
    // Given
    let fixture = Fixture::new();

    // When
    let broken = DonorRkaService::new(fixture.policy()).generate(
        fixture.generate_with_broken_csr_hash(1),
        &mut FakeBroker::default(),
    );

    // Then
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

#[test]
fn donor_accepts_same_authenticated_session_nonce_for_distinct_generates()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;

    // When
    let generated = donor.generate(fixture.generate_with_alias(2, [0xa2; 16]), &mut broker);

    // Then
    assert!(generated.is_ok());
    assert_eq!(broker.generated_requests, 2);
    Ok(())
}

#[test]
fn donor_rejects_tombstoned_operation_handle_collision_after_abort()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let collision = rka_sidecar::donor::RemoteOperationHandle::new([0xee; 16]);
    let mut broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    let first = donor.begin(fixture.begin(2), &mut broker)?;
    donor.abort(fixture.abort(3, first.operation_handle), &mut broker)?;

    // When
    let reused = donor.begin(fixture.begin(4), &mut broker);

    // Then
    assert_eq!(reused, Err(DonorError::HandleCollision));
    assert_eq!(broker.begin_calls, 2);
    assert_eq!(broker.delete_calls, 1);
    Ok(())
}

#[test]
fn donor_stale_operation_handle_aborts_live_and_quarantines()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    donor.begin(fixture.begin(2), &mut broker)?;

    // When
    let stale = donor.update(
        fixture.update(
            3,
            rka_sidecar::donor::RemoteOperationHandle::new([0xff; 16]),
            b"x",
        ),
        &mut broker,
    );

    // Then
    assert_eq!(stale, Err(DonorError::StaleHandle));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(broker.abort_calls, 1);
    assert_eq!(broker.delete_calls, 1);
    Ok(())
}

#[test]
fn donor_rejects_authoritative_irpc_mismatch_without_broker_generate() {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());

    // When
    let mismatch = donor.generate(fixture.generate_with_irpc(1, [0xfa; 32]), &mut broker);

    // Then
    assert_eq!(mismatch, Err(DonorError::IrpcIdentityMismatch));
    assert_eq!(broker.generated_requests, 0);
}

#[test]
fn donor_forwards_the_dispatch_selected_transcript_to_the_broker() {
    // Given
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());

    // When
    let generated = donor.generate(fixture.generate_with_transcript(1, [0xfa; 32]), &mut broker);

    // Then
    assert!(generated.is_ok());
    assert_eq!(broker.prior_transcripts, vec![[0xfa; 32]]);
}

#[test]
fn donor_broker_failures_are_terminal_and_expose_no_result()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let mut generate_broker = FakeBroker {
        fail_generate: true,
        ..FakeBroker::default()
    };
    let generated =
        DonorRkaService::new(fixture.policy()).generate(fixture.generate(1), &mut generate_broker);
    assert_eq!(generated, Err(DonorError::Broker));

    let mut update_broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(2), &mut update_broker)?;
    let operation = donor.begin(fixture.begin(3), &mut update_broker)?;
    update_broker.fail_update_aad = true;
    let updated = donor.update_aad(
        fixture.update(4, operation.operation_handle, b"aad"),
        &mut update_broker,
    );
    assert_eq!(updated, Err(DonorError::Broker));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(
        (update_broker.abort_calls, update_broker.delete_calls),
        (1, 1)
    );

    let mut delete_broker = FakeBroker::default();
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(5), &mut delete_broker)?;
    delete_broker.fail_delete = true;
    assert_eq!(
        donor.delete(fixture.delete(6), &mut delete_broker),
        Err(DonorError::Broker)
    );
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    Ok(())
}

#[test]
fn donor_rejects_remote_key_handle_collision() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let collision = rka_sidecar::donor::RemoteKeyHandle::new([0xdd; 16]);
    let mut broker = FakeBroker {
        forced_key: Some(collision),
        ..FakeBroker::default()
    };
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;

    let reused = donor.generate(fixture.generate_secondary(2), &mut broker);

    assert_eq!(reused, Err(DonorError::HandleCollision));
    assert_eq!(broker.generated_requests, 2);
    assert_eq!(broker.delete_calls, 1);
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    Ok(())
}

#[test]
fn donor_rejects_tombstoned_operation_after_finish_or_delete()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let collision = rka_sidecar::donor::RemoteOperationHandle::new([0xee; 16]);
    let mut broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    let first = donor.begin(fixture.begin(2), &mut broker)?;
    donor.finish(fixture.finish(3, first.operation_handle), &mut broker)?;
    donor.generate(fixture.generate_secondary(4), &mut broker)?;
    assert_eq!(
        donor.begin(fixture.begin_secondary(5), &mut broker),
        Err(DonorError::HandleCollision)
    );

    let mut broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(6), &mut broker)?;
    donor.begin(fixture.begin(7), &mut broker)?;
    donor.delete(fixture.delete(8), &mut broker)?;
    donor.generate(fixture.generate_secondary(9), &mut broker)?;
    assert_eq!(
        donor.begin(fixture.begin_secondary(10), &mut broker),
        Err(DonorError::HandleCollision)
    );
    Ok(())
}

#[test]
fn donor_live_operation_collision_quarantines_both_key_owners()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let collision = rka_sidecar::donor::RemoteOperationHandle::new([0xee; 16]);
    let mut broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut donor = DonorRkaService::new(fixture.policy());
    donor.generate(fixture.generate(1), &mut broker)?;
    donor.begin(fixture.begin(2), &mut broker)?;
    donor.generate(fixture.generate_secondary(3), &mut broker)?;

    let reused = donor.begin(fixture.begin_secondary(4), &mut broker);

    assert_eq!(reused, Err(DonorError::HandleCollision));
    assert_eq!(
        donor.key_state(fixture.alias()),
        Some(DonorKeyState::Quarantined)
    );
    assert_eq!(broker.abort_calls, 1);
    assert_eq!(broker.delete_calls, 2);
    Ok(())
}
