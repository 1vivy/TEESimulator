//! Bounded, host-testable transport traits.

use rka_protocol::Payload;
use thiserror::Error;

mod audit;
#[doc(hidden)]
pub mod audit_codec;
#[doc(hidden)]
pub mod direct_profile;
mod identity;
mod profile;
#[doc(hidden)]
pub mod profile_id;
mod session;
#[doc(hidden)]
pub mod session_lifecycle;
mod session_types;
mod tls;
#[doc(hidden)]
pub mod tls_handshake;
#[doc(hidden)]
pub mod tls_io;
mod tls_types;

pub use audit::{AuditChain, AuditEntry, AuditReceipt, ReceiptContext, ReceiptVerifier};
pub use direct_profile::{
    DirectEndpointProfile, DirectPath, DirectProfileInput, DirectProfileRotation,
    DirectReachability, DirectReadiness, DirectReadinessStatus,
};
pub use identity::{IdentityError, TransportIdentity};
pub use profile::{
    Endpoint, PairedProfile, ProfileError, ProfileInput, ProfileRotation, Role, TransportKind,
};
pub use session::SessionManager;
pub use session_lifecycle::{LiveSessionLease, SessionLifecycle};
pub use session_types::{
    AcceptedResponse, CsRng, PendingRequest, RequestContext, ResponseContext, SessionError,
    SessionScope, SystemCsRng,
};
pub use tls::{PinnedTlsClient, PinnedTlsServer, peer_spki_hash};
pub use tls_types::{
    AdmissionBinding, ClientPeer, ServerPeer, TlsAdmission, TlsCredentials, TlsError,
};

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
    /// The standard TLS or paired-profile checks failed.
    #[error("paired TLS validation failed")]
    Rejected,
    /// The one absolute I/O budget expired.
    #[error("paired transport deadline expired")]
    Deadline,
}

#[cfg(test)]
mod endpoint_profile_tests;
#[cfg(test)]
mod second_gate_audit_harness;
#[cfg(test)]
mod second_gate_tls_harness;
#[cfg(test)]
mod task10_tests;
#[cfg(test)]
mod third_gate_failure_budget;
