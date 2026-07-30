//! Non-secret protocol boundary failures.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("protocol payload must not be empty")]
    EmptyPayload,
    #[error("protocol payload is {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("record length does not match its prefix")]
    RecordLengthMismatch,
    #[error("CBOR item is truncated")]
    Truncated,
    #[error("CBOR uses a non-canonical representation")]
    NonCanonical,
    #[error("CBOR indefinite-length items are forbidden")]
    IndefiniteLength,
    #[error("CBOR nesting exceeds the fixed limit")]
    DepthExceeded,
    #[error("CBOR map keys must be unsigned integers")]
    NonIntegerKey,
    #[error("CBOR map keys are duplicate or out of order")]
    DuplicateOrUnorderedKey,
    #[error("protocol field is unknown")]
    UnknownField,
    #[error("protocol field has the wrong CBOR type")]
    WrongType,
    #[error("protocol field is missing")]
    MissingField,
    #[error("protocol field length is outside its fixed bound")]
    LengthOutOfRange,
    #[error("protocol integer value is unsupported")]
    UnsupportedValue,
    #[error("protocol field ordering is invalid")]
    InvalidOrdering,
    #[error("protocol material is forbidden on this boundary")]
    ForbiddenMaterial,
    #[error("cross-UID grants are unsupported")]
    CrossUidGrant,
    #[error("protocol state transition is invalid")]
    InvalidTransition,
}
