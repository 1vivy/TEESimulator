#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(clippy::unwrap_used, reason = "test setup must fail immediately")]

use ring::digest::{SHA256, digest};
use rka_rkp::{
    GOOGLE_ROOT_HASHES, GOOGLE_ROOTS_DER, RootBundle, RootTrustManager, TrustSessionError,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use x509_parser::parse_x509_certificate;

#[test]
fn production_bundle_contains_both_exact_published_der_roots() {
    assert_eq!(GOOGLE_ROOTS_DER.len(), 2);
    for (root, expected_hash) in GOOGLE_ROOTS_DER.iter().zip(GOOGLE_ROOT_HASHES) {
        assert!(parse_x509_certificate(root).is_ok());
        assert_eq!(digest(&SHA256, root).as_ref(), expected_hash);
    }
}

#[test]
fn rotation_pauses_admission_until_the_pinned_session_is_quiescent() {
    let manager = RootTrustManager::new(RootBundle::for_test(7, vec![[1; 32]]));
    let session = manager.begin().unwrap();

    assert_eq!(
        manager.pause_and_rotate(8, vec![[1; 32], [2; 32]], None),
        Err(TrustSessionError::ActiveSessions)
    );
    assert_eq!(manager.begin().unwrap_err(), TrustSessionError::Paused);
    assert_eq!(session.roots().epoch(), 7);

    drop(session);
    manager
        .pause_and_rotate(8, vec![[1; 32], [2; 32]], None)
        .unwrap();
    assert_eq!(manager.begin().unwrap().roots().epoch(), 8);
}

#[test]
fn concurrent_rotation_cannot_mutate_a_pinned_session_and_persists_before_swap() {
    let manager = Arc::new(RootTrustManager::new(RootBundle::for_test(
        7,
        vec![[1; 32]],
    )));
    let session = manager.begin().unwrap();
    std::thread::scope(|scope| {
        let rotating = Arc::clone(&manager);
        let result = scope
            .spawn(move || rotating.pause_and_rotate(8, vec![[1; 32], [2; 32]], None))
            .join()
            .unwrap();
        assert_eq!(result, Err(TrustSessionError::ActiveSessions));
    });
    assert_eq!(session.roots().epoch(), 7);
    drop(session);

    let persisted = AtomicU64::new(0);
    manager
        .pause_rotate_and_persist(8, vec![[1; 32], [2; 32]], None, |next| {
            persisted.store(next.epoch(), Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    assert_eq!(persisted.load(Ordering::SeqCst), 8);
    assert_eq!(manager.begin().unwrap().roots().epoch(), 8);
}
