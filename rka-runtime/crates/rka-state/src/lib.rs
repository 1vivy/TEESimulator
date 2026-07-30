//! Host-testable persistence boundary for sidecar state.

use thiserror::Error;

/// Maximum serialized state record size.
pub const MAX_STATE_BYTES: usize = 131_072;

/// Platform-independent bounded state store.
pub trait StateStore {
    /// Reads a record into caller-owned storage.
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError>;

    /// Atomically replaces one bounded record.
    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
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
