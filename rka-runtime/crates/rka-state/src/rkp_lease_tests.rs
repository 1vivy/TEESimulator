use super::*;
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
    })
    .unwrap()
}

fn evidence(order: u8) -> CertifiedKeyEvidence {
    let lease = lease(order);
    CertifiedKeyEvidence {
        batch_id: lease.metadata.batch_id,
        order,
        public_key_hash: lease.metadata.public_key_hash,
        leaf_spki_hash: lease.metadata.spki_hash,
        certificate_count: lease.metadata.chain.certificate_count,
        chain_hash: lease.metadata.chain.chain_hash,
    }
}

#[test]
fn activation_is_ordered_and_persisted() {
    let batch = RkpLeaseBatch::new(vec![lease(0), lease(1)]).unwrap();
    let token = verify_certified_evidence(&batch, &[evidence(0), evidence(1)]).unwrap();
    let store = MemoryStore {
        fail: false,
        value: RefCell::new(Vec::new()),
    };
    let active = batch.activate(&token, &store).unwrap();
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
    let token = verify_certified_evidence(&batch, &[evidence(0)]).unwrap();
    let store = MemoryStore {
        fail: true,
        value: RefCell::new(Vec::new()),
    };
    assert_eq!(
        batch.activate(&token, &store),
        Err(RkpLeaseError::State(StateError::Storage))
    );
}

#[test]
fn certification_evidence_mutations_are_rejected() {
    let batch = RkpLeaseBatch::new(vec![lease(0), lease(1)]).unwrap();
    let reordered = [evidence(1), evidence(0)];
    assert!(matches!(
        verify_certified_evidence(&batch, &reordered),
        Err(RkpLeaseError::Certification)
    ));
    let mut wrong_spki = [evidence(0), evidence(1)];
    wrong_spki[1].leaf_spki_hash = SpkiHash::new([99; 32]);
    assert!(matches!(
        verify_certified_evidence(&batch, &wrong_spki),
        Err(RkpLeaseError::Certification)
    ));
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
