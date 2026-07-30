//! Bounded protocol primitives shared by the RKA runtime crates.

use thiserror::Error;

/// Maximum accepted protocol payload size.
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;

/// A payload that has passed the protocol size boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    /// Parses a nonempty payload without allocating.
    pub const fn parse(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::EmptyPayload);
        }
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                actual: bytes.len(),
                maximum: MAX_PAYLOAD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the validated wire bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Failures produced while parsing the bounded protocol surface.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The frame carried no payload.
    #[error("protocol payload must not be empty")]
    EmptyPayload,
    /// The frame exceeded the fixed allocation boundary.
    #[error("protocol payload is {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge {
        /// Observed payload size.
        actual: usize,
        /// Accepted payload size.
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{MAX_PAYLOAD_BYTES, Payload, ProtocolError};

    #[test]
    fn payload_is_borrowed_when_within_limit() {
        let bytes = [7_u8; 4];
        let parsed = Payload::parse(&bytes);

        assert_eq!(parsed.map(Payload::as_bytes), Ok(bytes.as_slice()));
    }

    #[test]
    fn payload_is_rejected_when_over_limit() {
        let bytes = vec![0_u8; MAX_PAYLOAD_BYTES + 1];
        let parsed = Payload::parse(&bytes);

        assert_eq!(
            parsed,
            Err(ProtocolError::PayloadTooLarge {
                actual: MAX_PAYLOAD_BYTES + 1,
                maximum: MAX_PAYLOAD_BYTES,
            })
        );
    }
}
