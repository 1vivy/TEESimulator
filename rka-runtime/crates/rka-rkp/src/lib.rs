//! Host-testable boundary for remote key provisioning.

use thiserror::Error;

/// Maximum request or response body accepted by the provisioning adapter.
pub const MAX_PROVISIONING_BYTES: usize = 1_048_576;

/// Platform-independent provisioning adapter.
pub trait ProvisioningClient {
    /// Exchanges one bounded request and writes into caller-owned storage.
    fn exchange(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ProvisioningError>;
}

/// Provisioning boundary failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningError {
    /// A request crossed the fixed network boundary.
    #[error("provisioning request is {actual} bytes; maximum is {maximum}")]
    RequestTooLarge {
        /// Observed byte count.
        actual: usize,
        /// Accepted byte count.
        maximum: usize,
    },
    /// The caller-provided response storage is insufficient.
    #[error("response capacity is {actual} bytes; required is {required}")]
    ResponseCapacity {
        /// Available storage.
        actual: usize,
        /// Required storage.
        required: usize,
    },
    /// The platform adapter reported a transport failure.
    #[error("provisioning transport failed")]
    Transport,
}

/// Checks a provisioning request before a platform adapter receives it.
pub const fn validate_request(request: &[u8]) -> Result<(), ProvisioningError> {
    if request.len() > MAX_PROVISIONING_BYTES {
        return Err(ProvisioningError::RequestTooLarge {
            actual: request.len(),
            maximum: MAX_PROVISIONING_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_PROVISIONING_BYTES, ProvisioningError, validate_request};

    #[test]
    fn oversized_request_is_rejected_before_transport() {
        let request = vec![0_u8; MAX_PROVISIONING_BYTES + 1];
        let result = validate_request(&request);

        assert_eq!(
            result,
            Err(ProvisioningError::RequestTooLarge {
                actual: MAX_PROVISIONING_BYTES + 1,
                maximum: MAX_PROVISIONING_BYTES,
            })
        );
    }
}
