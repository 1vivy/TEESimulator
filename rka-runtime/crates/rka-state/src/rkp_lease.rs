use crate::{StateError, StateStore, validate_record};
use ring::digest::{SHA256, digest};
use thiserror::Error;

const MAX_LEASES: usize = 20;
const RECORD_KEY: &[u8] = b"rkp-leases-v1";

macro_rules! fixed_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $size]);

        impl $name {
            #[must_use]
            pub const fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
    };
}

fixed_id!(LeaseId, 16);
fixed_id!(BatchId, 16);
fixed_id!(PublicKeyHash, 32);
fixed_id!(SpkiHash, 32);
fixed_id!(IrpcIdentityHash, 32);
fixed_id!(RemoteKeyHandle, 32);
fixed_id!(ChainHash, 32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LeaseState {
    Certified,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "canonical chain metadata has a closed wire schema"
)]
pub struct PublicChainMetadata {
    pub chain_hash: ChainHash,
    pub certificate_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "canonical certified metadata has a closed persistence schema"
)]
pub struct CertifiedLeaseMetadata {
    pub lease_id: LeaseId,
    pub batch_id: BatchId,
    pub order: u8,
    pub public_key_hash: PublicKeyHash,
    pub spki_hash: SpkiHash,
    pub irpc_identity_hash: IrpcIdentityHash,
    pub remote_handle: RemoteKeyHandle,
    pub chain: PublicChainMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RkpLease {
    metadata: CertifiedLeaseMetadata,
    state: LeaseState,
}

impl RkpLease {
    /// Creates public metadata for a key whose certificate chain was validated.
    ///
    /// # Errors
    /// Returns an error for an empty chain.
    pub const fn certified(metadata: CertifiedLeaseMetadata) -> Result<Self, RkpLeaseError> {
        if metadata.chain.certificate_count == 0 {
            return Err(RkpLeaseError::InvalidMetadata);
        }
        Ok(Self {
            metadata,
            state: LeaseState::Certified,
        })
    }

    #[must_use]
    pub const fn metadata(&self) -> &CertifiedLeaseMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn state(&self) -> LeaseState {
        self.state
    }
}

#[derive(Debug)]
pub struct ValidatedCertificationToken {
    batch_id: BatchId,
    chain_hash: ChainHash,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RkpLeaseBatch {
    leases: Vec<RkpLease>,
}

impl RkpLeaseBatch {
    /// Builds an ordered, unique certified batch.
    ///
    /// # Errors
    /// Rejects empty, oversized, mixed, duplicate, or out-of-order batches.
    pub fn new(leases: Vec<RkpLease>) -> Result<Self, RkpLeaseError> {
        if leases.is_empty() || leases.len() > MAX_LEASES {
            return Err(RkpLeaseError::Count);
        }
        let batch = leases
            .first()
            .ok_or(RkpLeaseError::Count)?
            .metadata
            .batch_id;
        for (order, lease) in leases.iter().enumerate() {
            let expected = u8::try_from(order).map_err(|_| RkpLeaseError::Count)?;
            if leases.iter().take(order).any(|prior| {
                prior.metadata.lease_id == lease.metadata.lease_id
                    || prior.metadata.public_key_hash == lease.metadata.public_key_hash
                    || prior.metadata.spki_hash == lease.metadata.spki_hash
                    || prior.metadata.remote_handle == lease.metadata.remote_handle
            }) {
                return Err(RkpLeaseError::Duplicate);
            }
            if lease.metadata.batch_id != batch
                || lease.metadata.order != expected
                || lease.state != LeaseState::Certified
            {
                return Err(RkpLeaseError::Order);
            }
        }
        Ok(Self { leases })
    }

    #[must_use]
    pub fn leases(&self) -> &[RkpLease] {
        &self.leases
    }

    /// Durably records activation before exposing active leases.
    ///
    /// # Errors
    /// Rejects the wrong validation token or propagates storage failure.
    pub fn activate(
        mut self,
        token: &ValidatedCertificationToken,
        store: &dyn StateStore,
    ) -> Result<Self, RkpLeaseError> {
        let first = self.leases.first().ok_or(RkpLeaseError::Count)?;
        if token.batch_id != first.metadata.batch_id
            || self
                .leases
                .iter()
                .any(|lease| lease.metadata.chain.chain_hash != token.chain_hash)
        {
            return Err(RkpLeaseError::Certification);
        }
        self.leases
            .iter_mut()
            .for_each(|lease| lease.state = LeaseState::Active);
        let encoded = self.encode()?;
        validate_record(&encoded)?;
        store.replace(RECORD_KEY, &encoded)?;
        Ok(self)
    }

    fn encode(&self) -> Result<Vec<u8>, RkpLeaseError> {
        let capacity = self
            .leases
            .len()
            .checked_mul(210)
            .and_then(|size| size.checked_add(8))
            .ok_or(RkpLeaseError::Count)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(b"RKPL\x01");
        bytes.push(u8::try_from(self.leases.len()).map_err(|_| RkpLeaseError::Count)?);
        for lease in &self.leases {
            bytes.extend_from_slice(lease.metadata.lease_id.as_bytes());
            bytes.extend_from_slice(lease.metadata.batch_id.as_bytes());
            bytes.push(lease.metadata.order);
            bytes.extend_from_slice(lease.metadata.public_key_hash.as_bytes());
            bytes.extend_from_slice(lease.metadata.spki_hash.as_bytes());
            bytes.extend_from_slice(lease.metadata.irpc_identity_hash.as_bytes());
            bytes.extend_from_slice(lease.metadata.remote_handle.as_bytes());
            bytes.extend_from_slice(lease.metadata.chain.chain_hash.as_bytes());
            bytes.push(lease.metadata.chain.certificate_count);
            bytes.push(match lease.state {
                LeaseState::Certified => 1,
                LeaseState::Active => 2,
            });
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RkpLeaseError {
    #[error("lease count is outside 1..=20")]
    Count,
    #[error("lease metadata is invalid")]
    InvalidMetadata,
    #[error("lease order or batch is invalid")]
    Order,
    #[error("lease metadata is duplicated")]
    Duplicate,
    #[error("certification token does not match")]
    Certification,
    #[error(transparent)]
    State(#[from] StateError),
}

#[must_use]
pub fn hash_public_key(bytes: &[u8]) -> PublicKeyHash {
    let mut value = [0_u8; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    PublicKeyHash::new(value)
}

#[cfg(test)]
#[path = "rkp_lease_tests.rs"]
mod tests;
