use crate::StateError;
use crate::rkp_lease::{
    BatchId, ChainHash, LeaseId, PublicKeyHash, RkpLeaseBatch, RkpLeaseError, SpkiHash,
};
use ring::{
    digest::{Context, SHA256, digest},
    signature::{ED25519, UnparsedPublicKey},
};
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const DOMAIN: &[u8] = b"RKA-VALIDATED-CHAIN-v1\0";
const CONSUMPTION_DOMAIN: &[u8] = b"RKA-CONSUMED-RECEIPTS-v1\0";
const RECEIPT_ROOT: &str = "/data/adb/modules/tricky_store/rka/validated-receipts";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "signed receipt has a closed schema"
)]
pub struct ValidatedChainClaims {
    pub lease_id: LeaseId,
    pub batch_id: BatchId,
    pub order: u8,
    pub public_key_hash: PublicKeyHash,
    pub leaf_spki_hash: SpkiHash,
    pub chain_hash: ChainHash,
    pub certificate_count: u8,
    pub profile_epoch: u64,
}

impl ValidatedChainClaims {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(170);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(self.lease_id.as_bytes());
        bytes.extend_from_slice(self.batch_id.as_bytes());
        bytes.push(self.order);
        bytes.extend_from_slice(self.public_key_hash.as_bytes());
        bytes.extend_from_slice(self.leaf_spki_hash.as_bytes());
        bytes.extend_from_slice(self.chain_hash.as_bytes());
        bytes.push(self.certificate_count);
        bytes.extend_from_slice(&self.profile_epoch.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedChainReceipt {
    claims: ValidatedChainClaims,
    signature: [u8; 64],
}

impl ValidatedChainReceipt {
    #[must_use]
    pub const fn new(claims: ValidatedChainClaims, signature: [u8; 64]) -> Self {
        Self { claims, signature }
    }

    #[must_use]
    pub const fn claims(&self) -> &ValidatedChainClaims {
        &self.claims
    }
}

#[derive(Debug)]
pub struct ValidatedCertificationToken {
    pub(crate) batch_id: BatchId,
    pub(crate) chain_hash: ChainHash,
    pub(crate) binding_hash: [u8; 32],
}

#[derive(Debug)]
pub struct ValidatedReceiptRegistry {
    root: PathBuf,
}

impl ValidatedReceiptRegistry {
    /// Opens the module-owned durable receipt-consumption registry.
    ///
    /// # Errors
    /// Returns a storage error if the fixed registry directory cannot be opened or created.
    pub fn open() -> Result<Self, StateError> {
        Self::at(Path::new(RECEIPT_ROOT))
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: &Path) -> Result<Self, StateError> {
        Self::at(root)
    }

    fn at(root: &Path) -> Result<Self, StateError> {
        std::fs::create_dir_all(root).map_err(|_| StateError::Storage)?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StateError::Storage)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn consume_once(&self, receipt_identity: &[u8; 32]) -> Result<bool, StateError> {
        let path = self.root.join(hex(receipt_identity)?);
        let mut tombstone = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(_) => return Err(StateError::Storage),
        };
        tombstone
            .write_all(receipt_identity)
            .and_then(|()| tombstone.sync_all())
            .and_then(|()| File::open(&self.root)?.sync_all())
            .map_err(|_| StateError::Storage)?;
        Ok(true)
    }
}

impl ValidatedCertificationToken {
    pub(crate) fn consume_matches(self, batch: &RkpLeaseBatch) -> bool {
        batch.leases.first().is_some_and(|lease| {
            self.batch_id == lease.metadata().batch_id
                && self.binding_hash == batch_binding(batch)
                && batch
                    .leases
                    .iter()
                    .all(|item| item.metadata().chain.chain_hash == self.chain_hash)
        })
    }
}

/// Verifies signed validator receipts before minting a single-use activation capability.
///
/// # Errors
/// Rejects an invalid signature or any missing, reordered, replayed, or mismatched claim.
pub fn verify_validated_chain_receipts(
    pending: &RkpLeaseBatch,
    receipts: &[ValidatedChainReceipt],
    registry: &ValidatedReceiptRegistry,
) -> Result<ValidatedCertificationToken, RkpLeaseError> {
    if receipts.len() != pending.leases.len() || receipts.is_empty() {
        return Err(RkpLeaseError::Certification);
    }
    for (order, (lease, receipt)) in pending.leases.iter().zip(receipts).enumerate() {
        let metadata = lease.metadata();
        let claims = &receipt.claims;
        if claims.lease_id != metadata.lease_id
            || claims.batch_id != metadata.batch_id
            || claims.order != u8::try_from(order).map_err(|_| RkpLeaseError::Count)?
            || claims.order != metadata.order
            || claims.public_key_hash != metadata.public_key_hash
            || claims.leaf_spki_hash != metadata.spki_hash
            || claims.chain_hash != metadata.chain.chain_hash
            || claims.certificate_count != metadata.chain.certificate_count
            || claims.certificate_count == 0
            || claims.profile_epoch != metadata.profile_epoch
            || UnparsedPublicKey::new(&ED25519, metadata.validator_public_key.as_bytes())
                .verify(&claims.canonical_bytes(), &receipt.signature)
                .is_err()
        {
            return Err(RkpLeaseError::Certification);
        }
    }
    let first = pending
        .leases
        .first()
        .ok_or(RkpLeaseError::Certification)?
        .metadata();
    if !registry.consume_once(&receipt_set_identity(receipts))? {
        return Err(RkpLeaseError::Certification);
    }
    Ok(ValidatedCertificationToken {
        batch_id: first.batch_id,
        chain_hash: first.chain.chain_hash,
        binding_hash: batch_binding(pending),
    })
}

fn hex(bytes: &[u8]) -> Result<String, StateError> {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from_digit(u32::from(byte >> 4), 16).ok_or(StateError::Storage)?);
        encoded.push(char::from_digit(u32::from(byte & 0x0f), 16).ok_or(StateError::Storage)?);
    }
    Ok(encoded)
}

fn receipt_set_identity(receipts: &[ValidatedChainReceipt]) -> [u8; 32] {
    let mut digest = Context::new(&SHA256);
    digest.update(CONSUMPTION_DOMAIN);
    for receipt in receipts {
        digest.update(&receipt.claims.canonical_bytes());
        digest.update(&receipt.signature);
    }
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(digest.finish().as_ref());
    identity
}

fn batch_binding(batch: &RkpLeaseBatch) -> [u8; 32] {
    let mut bytes = Vec::new();
    for lease in &batch.leases {
        let metadata = lease.metadata();
        bytes.extend_from_slice(metadata.lease_id.as_bytes());
        bytes.extend_from_slice(metadata.batch_id.as_bytes());
        bytes.push(metadata.order);
        bytes.extend_from_slice(metadata.public_key_hash.as_bytes());
        bytes.extend_from_slice(metadata.spki_hash.as_bytes());
        bytes.extend_from_slice(metadata.chain.chain_hash.as_bytes());
        bytes.push(metadata.chain.certificate_count);
        bytes.extend_from_slice(&metadata.profile_epoch.to_be_bytes());
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(digest(&SHA256, &bytes).as_ref());
    hash
}

#[cfg(test)]
#[path = "rkp_receipt_tests.rs"]
mod tests;
