//! Bounded, host-testable transport traits.

use rka_protocol::Payload;
use thiserror::Error;

/// Platform-independent transport adapter.
pub trait Transport {
    /// Exchanges one validated frame into caller-owned output storage.
    fn exchange(&self, request: Payload<'_>, response: &mut [u8]) -> Result<usize, TransportError>;
}

/// Transport boundary failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TransportError {
    /// The paired endpoint could not be reached.
    #[error("paired endpoint is unavailable")]
    Unavailable,
    /// The peer response exceeded caller-owned storage.
    #[error("response capacity is {actual} bytes; required is {required}")]
    ResponseCapacity {
        /// Available storage.
        actual: usize,
        /// Required storage.
        required: usize,
    },
}
