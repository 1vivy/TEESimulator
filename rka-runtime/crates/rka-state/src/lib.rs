//! Host-testable persistence boundary for sidecar state.

use thiserror::Error;

mod failure_budget;
pub(crate) mod failure_budget_codec;
mod quarantine;
mod replay;
#[doc(hidden)]
pub mod replay_codec;
#[allow(
    missing_docs,
    reason = "typed lease names and fields are self-describing"
)]
mod rkp_lease;
#[allow(
    missing_docs,
    reason = "typed validated receipt names and fields are self-describing"
)]
mod rkp_receipt;
mod rkp_receipt_registry;
mod sensitive;
#[allow(
    missing_docs,
    reason = "the closed synthetic-lease record uses self-describing field and status names"
)]
mod synthetic_lease;

pub use failure_budget::{
    FAILURE_THRESHOLD, FAILURE_WINDOW_SECONDS, FailureAdmission, FailureBudget, FailureBudgetError,
    FailureBudgetNamespace,
};
pub use quarantine::{
    AmbiguousMaterial, CleanupIntent, CrashRecovery, MutationCrashState, QuarantineAction,
    QuarantineActions, QuarantineError, QuarantineLedger, QuarantineReason,
};
pub use replay::{PersistedTombstone, ReplayManager, TombstoneTime};
pub use rkp_lease::{
    BatchId, CertifiedLeaseMetadata, ChainHash, IrpcIdentityHash, LeaseId, LeaseState,
    PairedActivationRecord, PublicChainMetadata, PublicKeyHash, RemoteKeyHandle, RkpLease,
    RkpLeaseBatch, RkpLeaseError, SpkiHash, ValidatorPublicKey, hash_public_key,
};
pub use rkp_receipt::{
    ValidatedCertificationToken, ValidatedChainClaims, ValidatedChainReceipt,
    verify_validated_chain_receipts,
};
pub use rkp_receipt_registry::ValidatedReceiptRegistry;
pub use sensitive::SensitiveStateStore;
pub use synthetic_lease::{
    MAX_SYNTHETIC_LEASE_CERTIFICATE_BYTES, MAX_SYNTHETIC_LEASE_CERTIFICATES,
    MAX_SYNTHETIC_LEASE_CHAIN_BYTES, MAX_SYNTHETIC_LEASE_PKCS8_BYTES,
    MAX_SYNTHETIC_LEASE_STATE_BYTES, SyntheticLeaseBundle, SyntheticLeaseError,
    SyntheticLeaseInstall, SyntheticLeaseState,
};

/// Maximum serialized state record size.
pub const MAX_STATE_BYTES: usize = 131_072;

/// Platform-independent bounded state store.
pub trait StateStore {
    /// Reads a record into caller-owned storage.
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError>;

    /// Atomically replaces one bounded record.
    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError>;

    /// Returns donor-wide replay-record disk usage when the store can observe it.
    fn donor_replay_bytes(&self) -> Result<usize, StateError> {
        Ok(0)
    }
}

/// State boundary failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum StateError {
    /// A state record crossed the fixed storage boundary.
    #[error("state record is {actual} bytes; maximum is {maximum}")]
    RecordTooLarge {
        /// Observed byte count.
        actual: usize,
        /// Accepted byte count.
        maximum: usize,
    },
    /// The requested record does not exist.
    #[error("state record was not found")]
    Missing,
    /// The platform store failed.
    #[error("state store failed")]
    Storage,
    /// Stored bytes did not match the canonical state schema.
    #[error("state record is corrupt")]
    Corrupt,
    /// Retained records consumed the bounded persistent capacity.
    #[error("state capacity is exhausted")]
    Capacity,
    /// A retained replay key was observed again.
    #[error("replay was rejected")]
    Replay,
    /// The supplied monotonic time regressed.
    #[error("monotonic time regressed")]
    TimeRegression,
}

/// Checks a serialized record before any platform store receives it.
pub const fn validate_record(value: &[u8]) -> Result<(), StateError> {
    if value.len() > MAX_STATE_BYTES {
        return Err(StateError::RecordTooLarge {
            actual: value.len(),
            maximum: MAX_STATE_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_STATE_BYTES, StateError, validate_record};

    #[test]
    fn oversized_record_is_rejected_before_storage() {
        let record = vec![0_u8; MAX_STATE_BYTES + 1];
        let result = validate_record(&record);

        assert_eq!(
            result,
            Err(StateError::RecordTooLarge {
                actual: MAX_STATE_BYTES + 1,
                maximum: MAX_STATE_BYTES,
            })
        );
    }
}
