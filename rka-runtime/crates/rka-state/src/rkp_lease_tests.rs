use super::*;
use crate::{ValidatedChainClaims, ValidatedChainReceipt, verify_validated_chain_receipts};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::cell::RefCell;

struct MemoryStore {
    fail: bool,
    value: RefCell<Vec<u8>>,
}

impl StateStore for MemoryStore {
    fn read(&self, _: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self.value.borrow();
        output
            .get_mut(..value.len())
            .ok_or(StateError::Storage)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, _: &[u8], value: &[u8]) -> Result<(), StateError> {
        if self.fail {
            return Err(StateError::Storage);
        }
        self.value.replace(value.to_vec());
        Ok(())
    }
}

fn lease(order: u8) -> RkpLease {
    let (lease, public, spki, handle) = match order {
        0 => (1, 2, 3, 5),
        1 => (2, 3, 4, 6),
        _ => (3, 4, 5, 7),
    };
    RkpLease::certified(CertifiedLeaseMetadata {
        lease_id: LeaseId::new([lease; 16]),
        batch_id: BatchId::new([7; 16]),
        order,
        public_key_hash: PublicKeyHash::new([public; 32]),
        spki_hash: SpkiHash::new([spki; 32]),
        irpc_identity_hash: IrpcIdentityHash::new([4; 32]),
        remote_handle: RemoteKeyHandle::new([handle; 32]),
        chain: PublicChainMetadata {
            chain_hash: ChainHash::new([9; 32]),
            certificate_count: 2,
        },
        validator_public_key: validator_public_key(42),
        profile_epoch: 17,
    })
    .unwrap()
}

fn claims(order: u8) -> ValidatedChainClaims {
    let lease = lease(order);
    ValidatedChainClaims {
        lease_id: lease.metadata.lease_id,
        batch_id: lease.metadata.batch_id,
        order,
        public_key_hash: lease.metadata.public_key_hash,
        leaf_spki_hash: lease.metadata.spki_hash,
        certificate_count: lease.metadata.chain.certificate_count,
        chain_hash: lease.metadata.chain.chain_hash,
        profile_epoch: lease.metadata.profile_epoch,
    }
}

fn validator(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn validator_public_key(seed: u8) -> ValidatorPublicKey {
    ValidatorPublicKey::new(validator(seed).public_key().as_ref().try_into().unwrap())
}

fn receipt(order: u8, seed: u8) -> ValidatedChainReceipt {
    let claims = claims(order);
    let signature = validator(seed).sign(&claims.canonical_bytes());
    ValidatedChainReceipt::new(claims, signature.as_ref().try_into().unwrap())
}

#[test]
fn activation_is_ordered_and_persisted() {
    let batch = RkpLeaseBatch::new(vec![lease(0), lease(1)]).unwrap();
    let token = verify_validated_chain_receipts(&batch, &[receipt(0, 42), receipt(1, 42)]).unwrap();
    let store = MemoryStore {
        fail: false,
        value: RefCell::new(Vec::new()),
    };
    let active = batch.activate(token, &store).unwrap();
    assert_eq!(
        active
            .leases()
            .iter()
            .map(|lease| lease.metadata.order)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert!(
        active
            .leases()
            .iter()
            .all(|lease| lease.state == LeaseState::Active)
    );
    assert!(!store.value.borrow().is_empty());
}

#[test]
fn duplicate_and_reordered_batches_are_rejected() {
    assert_eq!(
        RkpLeaseBatch::new(vec![lease(1), lease(0)]),
        Err(RkpLeaseError::Order)
    );
    assert_eq!(
        RkpLeaseBatch::new(vec![lease(0), lease(0)]),
        Err(RkpLeaseError::Duplicate)
    );
}

#[test]
fn storage_failure_prevents_activation_exposure() {
    let batch = RkpLeaseBatch::new(vec![lease(0)]).unwrap();
    let token = verify_validated_chain_receipts(&batch, &[receipt(0, 42)]).unwrap();
    let store = MemoryStore {
        fail: true,
        value: RefCell::new(Vec::new()),
    };
    assert_eq!(
        batch.activate(token, &store),
        Err(RkpLeaseError::State(StateError::Storage))
    );
}

#[test]
fn signed_receipt_mutations_and_wrong_validator_are_rejected() {
    let batch = RkpLeaseBatch::new(vec![lease(0), lease(1)]).unwrap();
    let reordered = [receipt(1, 42), receipt(0, 42)];
    assert!(matches!(
        verify_validated_chain_receipts(&batch, &reordered),
        Err(RkpLeaseError::Certification)
    ));
    let mut wrong_spki = claims(1);
    wrong_spki.leaf_spki_hash = SpkiHash::new([99; 32]);
    let signature = validator(42).sign(&wrong_spki.canonical_bytes());
    let wrong_spki = ValidatedChainReceipt::new(wrong_spki, signature.as_ref().try_into().unwrap());
    assert!(matches!(
        verify_validated_chain_receipts(&batch, &[receipt(0, 42), wrong_spki]),
        Err(RkpLeaseError::Certification)
    ));
    assert!(matches!(
        verify_validated_chain_receipts(&batch, &[receipt(0, 43), receipt(1, 43)]),
        Err(RkpLeaseError::Certification)
    ));
}

#[test]
fn forged_signature_and_cross_lease_replay_are_rejected() {
    let batch = RkpLeaseBatch::new(vec![lease(0)]).unwrap();
    let forged = ValidatedChainReceipt::new(claims(0), [0; 64]);
    assert_eq!(
        verify_validated_chain_receipts(&batch, &[forged]).unwrap_err(),
        RkpLeaseError::Certification
    );

    let mut replay_target = lease(0);
    replay_target.metadata.lease_id = LeaseId::new([88; 16]);
    let replay_target = RkpLeaseBatch::new(vec![replay_target]).unwrap();
    assert_eq!(
        verify_validated_chain_receipts(&replay_target, &[receipt(0, 42)]).unwrap_err(),
        RkpLeaseError::Certification
    );
}

fn public_boundary_is_safe(source: &str) -> bool {
    let forbidden_names = ["keyBlob", "private_bytes", "Binder", "alias"];
    !forbidden_names.iter().any(|name| source.contains(name))
        && !source.lines().any(|line| {
            line.trim_start().starts_with("pub ")
                && (line.contains("Vec<u8>") || line.contains("HashMap"))
        })
}

#[test]
fn production_public_boundary_rejects_secret_fields_and_mutation() {
    let source = include_str!("rkp_lease.rs");
    assert!(public_boundary_is_safe(source));
    let mutated = format!("{source}\npub keyBlob: Vec<u8>,");
    assert!(!public_boundary_is_safe(&mutated));
}
