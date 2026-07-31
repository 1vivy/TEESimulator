#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(clippy::unwrap_used, reason = "test setup must fail immediately")]

use ring::digest::{SHA256, digest};
use rka_rkp::{
    GOOGLE_ROOT_HASHES, GOOGLE_ROOTS_DER, RootBundle, RootTrustManager, TrustSessionError,
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
