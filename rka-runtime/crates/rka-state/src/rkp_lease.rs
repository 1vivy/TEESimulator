use crate::rkp_receipt::ValidatedCertificationToken;
use crate::{StateError, StateStore, validate_record};
use ring::digest::{SHA256, digest};
use thiserror::Error;

const MAX_LEASES: usize = 20;
const RECORD_KEY: &[u8] = b"rkp-leases-v1";
const PAIRED_RECORD_KEY: &[u8] = b"paired-activation-v1";

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
fixed_id!(ValidatorPublicKey, 32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    missing_docs,
    reason = "the persisted pairing schema is frozen and decoded as a closed record"
)]
pub struct PairedActivationRecord {
    pub peer_spki_hash: [u8; 32],
    pub profile_id_hash: [u8; 32],
    pub profile_epoch: u64,
    pub candidate_identity_hash: [u8; 32],
    pub session_id: [u8; 32],
    pub candidate_nonce: [u8; 32],
    pub donor_nonce: [u8; 32],
    pub prior_transcript_hash: [u8; 32],
}

#[allow(
    missing_docs,
    reason = "persist and load are the complete internal durable-record boundary"
)]
impl PairedActivationRecord {
    pub fn persist(&self, store: &dyn StateStore) -> Result<(), StateError> {
        let mut encoded = Vec::with_capacity(237);
        encoded.extend_from_slice(b"RKPA\x01");
        encoded.extend_from_slice(&self.peer_spki_hash);
        encoded.extend_from_slice(&self.profile_id_hash);
        encoded.extend_from_slice(&self.profile_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.candidate_identity_hash);
        encoded.extend_from_slice(&self.session_id);
        encoded.extend_from_slice(&self.candidate_nonce);
        encoded.extend_from_slice(&self.donor_nonce);
        encoded.extend_from_slice(&self.prior_transcript_hash);
        validate_record(&encoded)?;
        store.replace(PAIRED_RECORD_KEY, &encoded)
    }

    pub fn load(store: &dyn StateStore) -> Result<Self, StateError> {
        let mut encoded = [0_u8; 237];
        let length = store.read(PAIRED_RECORD_KEY, &mut encoded)?;
        if length != encoded.len() || encoded.get(..5) != Some(b"RKPA\x01") {
            return Err(StateError::Corrupt);
        }
        let mut cursor = LeaseCursor::new(&encoded[5..]);
        let record = Self {
            peer_spki_hash: cursor.array().map_err(state_error)?,
            profile_id_hash: cursor.array().map_err(state_error)?,
            profile_epoch: cursor.u64().map_err(state_error)?,
            candidate_identity_hash: cursor.array().map_err(state_error)?,
            session_id: cursor.array().map_err(state_error)?,
            candidate_nonce: cursor.array().map_err(state_error)?,
            donor_nonce: cursor.array().map_err(state_error)?,
            prior_transcript_hash: cursor.array().map_err(state_error)?,
        };
        cursor.finish().map_err(state_error)?;
        Ok(record)
    }
}

const fn state_error(error: RkpLeaseError) -> StateError {
    match error {
        RkpLeaseError::State(state) => state,
        RkpLeaseError::Count
        | RkpLeaseError::InvalidMetadata
        | RkpLeaseError::Order
        | RkpLeaseError::Duplicate
        | RkpLeaseError::Certification => StateError::Corrupt,
    }
}

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
    pub validator_public_key: ValidatorPublicKey,
    pub profile_epoch: u64,
    pub phase_hashes: [[u8; 32]; 5],
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

#[derive(Debug, Eq, PartialEq)]
pub struct RkpLeaseBatch {
    pub(crate) leases: Vec<RkpLease>,
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
        let first_metadata = leases.first().ok_or(RkpLeaseError::Count)?.metadata;
        let batch = first_metadata.batch_id;
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
                || lease.metadata.validator_public_key != first_metadata.validator_public_key
                || lease.metadata.profile_epoch != first_metadata.profile_epoch
                || lease.metadata.phase_hashes != first_metadata.phase_hashes
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
        token: ValidatedCertificationToken,
        store: &dyn StateStore,
    ) -> Result<Self, RkpLeaseError> {
        if !token.consume_matches(&self) {
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

    /// Reopens the sole canonical active lease batch.
    ///
    /// # Errors
    /// Fails closed when the record is missing, malformed, non-active, or no
    /// longer satisfies the ordered batch invariants.
    pub fn load_active(store: &dyn StateStore) -> Result<Self, RkpLeaseError> {
        let mut encoded = vec![0_u8; crate::MAX_STATE_BYTES];
        let length = store.read(RECORD_KEY, &mut encoded)?;
        let bytes = encoded
            .get(..length)
            .ok_or(RkpLeaseError::State(StateError::Corrupt))?;
        let mut cursor = LeaseCursor::new(bytes);
        if cursor.take(5)? != b"RKPL\x01" {
            return Err(StateError::Corrupt.into());
        }
        let count = usize::from(cursor.u8()?);
        if !(1..=MAX_LEASES).contains(&count) {
            return Err(RkpLeaseError::Count);
        }
        let mut leases = Vec::with_capacity(count);
        for _ in 0..count {
            leases.push(RkpLease {
                metadata: CertifiedLeaseMetadata {
                    lease_id: LeaseId::new(cursor.array()?),
                    batch_id: BatchId::new(cursor.array()?),
                    order: cursor.u8()?,
                    public_key_hash: PublicKeyHash::new(cursor.array()?),
                    spki_hash: SpkiHash::new(cursor.array()?),
                    irpc_identity_hash: IrpcIdentityHash::new(cursor.array()?),
                    remote_handle: RemoteKeyHandle::new(cursor.array()?),
                    chain: PublicChainMetadata {
                        chain_hash: ChainHash::new(cursor.array()?),
                        certificate_count: cursor.u8()?,
                    },
                    validator_public_key: ValidatorPublicKey::new(cursor.array()?),
                    profile_epoch: cursor.u64()?,
                    phase_hashes: [
                        cursor.array()?,
                        cursor.array()?,
                        cursor.array()?,
                        cursor.array()?,
                        cursor.array()?,
                    ],
                },
                state: match cursor.u8()? {
                    2 => LeaseState::Active,
                    _ => return Err(StateError::Corrupt.into()),
                },
            });
        }
        cursor.finish()?;
        let batch = Self::new_active(leases)?;
        Ok(batch)
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
            bytes.extend_from_slice(lease.metadata.validator_public_key.as_bytes());
            bytes.extend_from_slice(&lease.metadata.profile_epoch.to_be_bytes());
            for hash in lease.metadata.phase_hashes {
                bytes.extend_from_slice(&hash);
            }
            bytes.push(match lease.state {
                LeaseState::Certified => 1,
                LeaseState::Active => 2,
            });
        }
        Ok(bytes)
    }

    fn new_active(leases: Vec<RkpLease>) -> Result<Self, RkpLeaseError> {
        let mut certified = leases.clone();
        for lease in &mut certified {
            lease.state = LeaseState::Certified;
        }
        Self::new(certified)?;
        Ok(Self { leases })
    }
}

struct LeaseCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LeaseCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RkpLeaseError> {
        let end = self.offset.checked_add(length).ok_or(StateError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StateError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RkpLeaseError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StateError::Corrupt.into())
    }

    fn u8(&mut self) -> Result<u8, RkpLeaseError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| StateError::Corrupt.into())
    }

    fn u64(&mut self) -> Result<u64, RkpLeaseError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    const fn finish(self) -> Result<(), RkpLeaseError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RkpLeaseError::State(StateError::Corrupt))
        }
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
