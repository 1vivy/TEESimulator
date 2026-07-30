use thiserror::Error;

#[doc = "Typed bridge failure containing no payload body."]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum BridgeError {
    #[doc = "Magic bytes differ from RKB1."]
    #[error("bridge frame magic rejected")]
    BadMagic,
    #[doc = "Version is not one."]
    #[error("bridge version rejected")]
    UnsupportedVersion,
    #[doc = "Direction differs from the endpoint role."]
    #[error("bridge direction rejected")]
    WrongDirection,
    #[doc = "Tag is outside the closed tag set."]
    #[error("bridge tag rejected")]
    UnknownTag,
    #[doc = "Tag is invalid for this endpoint role."]
    #[error("bridge tag is invalid for role")]
    UnexpectedTag,
    #[doc = "Flags or reserved bytes are nonzero."]
    #[error("bridge reserved field rejected")]
    ReservedBits,
    #[doc = "Body length is zero."]
    #[error("bridge frame is empty")]
    EmptyFrame,
    #[doc = "Body length exceeds one MiB."]
    #[error("bridge frame exceeds bound")]
    FrameTooLarge,
    #[doc = "Header or body ended early."]
    #[error("bridge frame is truncated")]
    Truncated,
    #[doc = "Body contains noncanonical bytes."]
    #[error("bridge frame is noncanonical")]
    NonCanonical,
    #[doc = "A DTO field exceeds its fixed bound."]
    #[error("bridge value exceeds bound")]
    ValueTooLarge,
    #[doc = "Response identifier or kind differs."]
    #[error("bridge correlation rejected")]
    Correlation,
    #[doc = "Reconnect generation differs."]
    #[error("bridge generation rejected")]
    Generation,
    #[doc = "Active capacity is exhausted."]
    #[error("bridge capacity exhausted")]
    Capacity,
    #[doc = "Queue capacity is exhausted."]
    #[error("bridge queue exhausted")]
    QueueSaturated,
    #[doc = "Aggregate budget expired."]
    #[error("bridge deadline exceeded")]
    Deadline,
    #[doc = "Work was explicitly cancelled."]
    #[error("bridge operation cancelled")]
    Cancelled,
    #[doc = "The authenticated peer disconnected."]
    #[error("bridge peer died")]
    PeerDied,
    #[doc = "Kernel or procfs identity differs."]
    #[error("bridge peer identity rejected")]
    PeerIdentity,
    #[doc = "Protected identity record is invalid."]
    #[error("bridge trusted state rejected")]
    TrustedState,
    #[doc = "A synchronization or stream operation failed."]
    #[error("bridge I/O failed")]
    Io,
    #[doc = "A bounded allocation could not be reserved."]
    #[error("bridge allocation failed")]
    Allocation,
}
