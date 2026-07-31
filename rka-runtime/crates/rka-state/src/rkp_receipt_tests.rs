use super::*;
use crate::rkp_lease::{
    BatchId, CertifiedLeaseMetadata, ChainHash, IrpcIdentityHash, LeaseId, PublicChainMetadata,
    PublicKeyHash, RemoteKeyHandle, RkpLease, RkpLeaseBatch, RkpLeaseError, SpkiHash,
    ValidatorPublicKey,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

fn lease(order: u8, lease_id: u8) -> RkpLease {
    RkpLease::certified(CertifiedLeaseMetadata {
        lease_id: LeaseId::new([lease_id; 16]),
        batch_id: BatchId::new([7; 16]),
        order,
        public_key_hash: PublicKeyHash::new([order.saturating_add(2); 32]),
        spki_hash: SpkiHash::new([order.saturating_add(3); 32]),
        irpc_identity_hash: IrpcIdentityHash::new([4; 32]),
        remote_handle: RemoteKeyHandle::new([order.saturating_add(5); 32]),
        chain: PublicChainMetadata {
            chain_hash: ChainHash::new([9; 32]),
            certificate_count: 2,
        },
        validator_public_key: validator_public_key(42),
        profile_epoch: 17,
    })
    .unwrap()
}

fn claims(order: u8, lease_id: u8) -> ValidatedChainClaims {
    let lease = lease(order, lease_id);
    let metadata = lease.metadata();
    ValidatedChainClaims {
        lease_id: metadata.lease_id,
        batch_id: metadata.batch_id,
        order,
        public_key_hash: metadata.public_key_hash,
        leaf_spki_hash: metadata.spki_hash,
        certificate_count: metadata.chain.certificate_count,
        chain_hash: metadata.chain.chain_hash,
        profile_epoch: metadata.profile_epoch,
    }
}

fn validator(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn validator_public_key(seed: u8) -> ValidatorPublicKey {
    ValidatorPublicKey::new(validator(seed).public_key().as_ref().try_into().unwrap())
}

fn receipt(order: u8, lease_id: u8, seed: u8) -> ValidatedChainReceipt {
    let claims = claims(order, lease_id);
    let signature = validator(seed).sign(&claims.canonical_bytes());
    ValidatedChainReceipt::new(claims, signature.as_ref().try_into().unwrap())
}

fn registry() -> (PathBuf, ValidatedReceiptRegistry) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rka-receipt-registry-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry = ValidatedReceiptRegistry::for_test(&root).unwrap();
    (root, registry)
}

fn race_worker(
    registry: Arc<ValidatedReceiptRegistry>,
    barrier: Arc<Barrier>,
) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        barrier.wait();
        verify_validated_chain_receipts(
            &RkpLeaseBatch::new(vec![lease(0, 1)]).unwrap(),
            &[receipt(0, 1, 42)],
            &registry,
        )
        .is_ok()
    })
}

#[test]
fn signed_receipt_mutations_and_wrong_validator_are_rejected() {
    let batch = RkpLeaseBatch::new(vec![lease(0, 1), lease(1, 2)]).unwrap();
    let (root, registry) = registry();
    let reordered = [receipt(1, 2, 42), receipt(0, 1, 42)];
    assert_eq!(
        verify_validated_chain_receipts(&batch, &reordered, &registry).unwrap_err(),
        RkpLeaseError::Certification
    );
    let mut wrong_spki = claims(1, 2);
    wrong_spki.leaf_spki_hash = SpkiHash::new([99; 32]);
    let signature = validator(42).sign(&wrong_spki.canonical_bytes());
    let wrong_spki = ValidatedChainReceipt::new(wrong_spki, signature.as_ref().try_into().unwrap());
    assert_eq!(
        verify_validated_chain_receipts(&batch, &[receipt(0, 1, 42), wrong_spki], &registry,)
            .unwrap_err(),
        RkpLeaseError::Certification
    );
    assert_eq!(
        verify_validated_chain_receipts(
            &batch,
            &[receipt(0, 1, 43), receipt(1, 2, 43)],
            &registry,
        )
        .unwrap_err(),
        RkpLeaseError::Certification
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn forged_signature_and_cross_lease_replay_are_rejected() {
    let batch = RkpLeaseBatch::new(vec![lease(0, 1)]).unwrap();
    let (root, registry) = registry();
    let forged = ValidatedChainReceipt::new(claims(0, 1), [0; 64]);
    assert_eq!(
        verify_validated_chain_receipts(&batch, &[forged], &registry).unwrap_err(),
        RkpLeaseError::Certification
    );
    let replay_target = RkpLeaseBatch::new(vec![lease(0, 88)]).unwrap();
    assert_eq!(
        verify_validated_chain_receipts(&replay_target, &[receipt(0, 1, 42)], &registry,)
            .unwrap_err(),
        RkpLeaseError::Certification
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_replay_is_rejected_after_registry_reopen() {
    let receipts = [receipt(0, 1, 42)];
    let (root, first_registry) = registry();
    assert!(
        verify_validated_chain_receipts(
            &RkpLeaseBatch::new(vec![lease(0, 1)]).unwrap(),
            &receipts,
            &first_registry,
        )
        .is_ok()
    );
    drop(first_registry);
    let reopened = ValidatedReceiptRegistry::for_test(&root).unwrap();
    assert_eq!(
        verify_validated_chain_receipts(
            &RkpLeaseBatch::new(vec![lease(0, 1)]).unwrap(),
            &receipts,
            &reopened,
        )
        .unwrap_err(),
        RkpLeaseError::Certification
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_exact_receipt_consumption_has_one_winner() {
    let (root, registry) = registry();
    let registry = Arc::new(registry);
    let barrier = Arc::new(Barrier::new(2));
    let workers = [
        race_worker(Arc::clone(&registry), Arc::clone(&barrier)),
        race_worker(Arc::clone(&registry), Arc::clone(&barrier)),
    ];
    let winners = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(1, winners);
    drop(registry);
    std::fs::remove_dir_all(root).unwrap();
}
