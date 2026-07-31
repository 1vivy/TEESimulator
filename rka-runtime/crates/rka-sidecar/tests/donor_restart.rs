#![allow(
    dead_code,
    missing_docs,
    reason = "the shared lifecycle fixture intentionally exposes more cases than this split suite"
)]

#[path = "donor_rka/support.rs"]
mod donor_rka_support;

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use donor_rka_support::{FakeBroker, Fixture};
use rka_sidecar::donor::{DonorError, DonorRkaService, RemoteOperationHandle};

#[test]
fn donor_reopen_rejects_the_same_durable_operation_tuple() -> Result<(), Box<dyn std::error::Error>>
{
    // Given
    let root = unique_root();
    let fixture = Fixture::new();
    let collision = RemoteOperationHandle::new([0xee; 16]);
    let mut first_broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut first = DonorRkaService::new_durable(fixture.policy(), &root);
    first.generate(fixture.generate(1), &mut first_broker)?;
    first.begin(fixture.begin(2), &mut first_broker)?;
    drop(first);
    let mut second_broker = FakeBroker {
        forced_operation: Some(collision),
        ..FakeBroker::default()
    };
    let mut reopened = DonorRkaService::new_durable(fixture.policy(), &root);
    reopened.generate(fixture.generate(1), &mut second_broker)?;

    // When
    let result = reopened.begin(fixture.begin(2), &mut second_broker);

    // Then
    assert_eq!(result, Err(DonorError::HandleCollision));
    assert_eq!(second_broker.abort_calls, 1);
    assert_eq!(second_broker.delete_calls, 1);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn tombstone_storage_failure_cleans_only_the_unexposed_begin()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root();
    fs::write(&root, b"not-a-directory")?;
    let fixture = Fixture::new();
    let mut broker = FakeBroker::default();
    let mut donor = DonorRkaService::new_durable(fixture.policy(), &root);
    donor.generate(fixture.generate(1), &mut broker)?;

    // When
    let result = donor.begin(fixture.begin(2), &mut broker);

    // Then
    assert_eq!(result, Err(DonorError::Storage));
    assert_eq!(broker.abort_calls, 1);
    assert_eq!(broker.finish_calls, 0);
    assert_eq!(broker.delete_calls, 1);
    fs::remove_file(root)?;
    Ok(())
}

fn unique_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rka-donor-restart-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
