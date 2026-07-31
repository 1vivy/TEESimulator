#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(
    clippy::unwrap_used,
    reason = "fixture construction must fail immediately"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use rka_rkp::outcome::{
    AttemptDigests, AttemptIdentity, AttemptIds, DurableResponseJournal, FailureDisposition,
    PostFailure, UploadProgress, validate_fresh_attempt,
};
use rka_state::{StateError, StateStore};

#[derive(Default)]
struct MemoryStore(RefCell<BTreeMap<Vec<u8>, Vec<u8>>>);

impl StateStore for MemoryStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .0
            .borrow()
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Storage)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.0.borrow_mut().insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

fn attempt(seed: u8) -> AttemptIdentity {
    AttemptIdentity::new(
        AttemptIds::new([seed; 16], [seed.wrapping_add(1); 16]),
        AttemptDigests::new([seed.wrapping_add(2); 32], [seed.wrapping_add(3); 32]),
        vec![[seed.wrapping_add(4); 32]],
    )
    .unwrap()
}

#[test]
fn connect_before_upload_is_the_only_retryable_post_failure() {
    assert_eq!(
        FailureDisposition::classify(UploadProgress::NoRequestByteWritten, PostFailure::Connect),
        FailureDisposition::Retryable
    );
    for failure in [
        PostFailure::Dns,
        PostFailure::Tls,
        PostFailure::Encode,
        PostFailure::Local,
        PostFailure::Config,
        PostFailure::Timeout,
        PostFailure::LostResponse,
        PostFailure::SidecarDeath,
        PostFailure::MissingDurableResponse,
    ] {
        assert_eq!(
            FailureDisposition::classify(UploadProgress::NoRequestByteWritten, failure),
            FailureDisposition::PostAmbiguous
        );
    }
    for progress in [
        UploadProgress::UploadMayHaveBegun,
        UploadProgress::UploadCompleted,
    ] {
        for failure in [
            PostFailure::Timeout,
            PostFailure::LostResponse,
            PostFailure::SidecarDeath,
            PostFailure::MissingDurableResponse,
        ] {
            assert_eq!(
                FailureDisposition::classify(progress, failure),
                FailureDisposition::PostAmbiguous
            );
        }
    }
}

#[test]
fn post_ambiguous_requires_fresh_batch() {
    let old = attempt(1);
    let fresh = attempt(20);
    assert!(validate_fresh_attempt(&old, &fresh).is_ok());
    assert!(validate_fresh_attempt(&old, &attempt(1)).is_err());

    let reused_challenge = AttemptIdentity::new(
        AttemptIds::new([30; 16], [31; 16]),
        AttemptDigests::new(*old.challenge_hash(), [33; 32]),
        vec![[34; 32]],
    )
    .unwrap();
    assert!(validate_fresh_attempt(&old, &reused_challenge).is_err());
}

#[test]
fn durable_response_replays_only_for_the_exact_request_without_upload() {
    let store = MemoryStore::default();
    let journal = DurableResponseJournal::new(&store);
    let identity = attempt(7);
    journal
        .record_validated(&identity, b"validated-response")
        .unwrap();

    assert_eq!(
        journal.replay_for(&identity).unwrap(),
        Some(b"validated-response".to_vec())
    );
    assert!(journal.replay_for(&attempt(40)).is_err());
}
