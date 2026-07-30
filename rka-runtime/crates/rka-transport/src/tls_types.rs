use core::fmt;
use std::time::Duration;

use rka_protocol::sha256;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use thiserror::Error;

const ADMISSION_DOMAIN: &[u8] = b"TEESIM-RKA-V2/ADMISSION\0";

/// Public transcript coordinates bound into reciprocal admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AdmissionBinding {
    /// Deterministic paired-profile identifier.
    pub profile_id: [u8; 32],
    /// Candidate-owned session identifier.
    pub session_id: [u8; 32],
    /// Candidate-owned nonce.
    pub candidate_nonce: [u8; 32],
    /// Transcript hash before the first application request.
    pub transcript_hash: [u8; 32],
}

impl AdmissionBinding {
    pub(crate) fn token(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(ADMISSION_DOMAIN.len().saturating_add(128));
        bytes.extend_from_slice(ADMISSION_DOMAIN);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.candidate_nonce);
        bytes.extend_from_slice(&self.transcript_hash);
        sha256(&bytes)
    }
}

/// Bounded certificate chain and secret signing key for rustls.
#[non_exhaustive]
pub struct TlsCredentials {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

impl fmt::Debug for TlsCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsCredentials([redacted identity material])")
    }
}

impl TlsCredentials {
    /// Creates credentials already loaded from protected identity storage.
    #[must_use]
    pub const fn new(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self { chain, key }
    }
}

/// Exact server trust, name, and pin expected by a candidate.
#[non_exhaustive]
pub struct ClientPeer {
    pub(crate) trust: Vec<CertificateDer<'static>>,
    pub(crate) name: ServerName<'static>,
    pub(crate) pin: [u8; 32],
}

impl fmt::Debug for ClientPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientPeer([redacted trust and pin])")
    }
}

impl ClientPeer {
    /// Creates standard-name validation inputs plus the post-handshake pin.
    #[must_use]
    pub const fn new(
        trust: Vec<CertificateDer<'static>>,
        name: ServerName<'static>,
        pin: [u8; 32],
    ) -> Self {
        Self { trust, name, pin }
    }
}

/// Exact candidate trust and pin expected by a donor.
#[non_exhaustive]
pub struct ServerPeer {
    pub(crate) trust: Vec<CertificateDer<'static>>,
    pub(crate) pin: [u8; 32],
}

impl fmt::Debug for ServerPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerPeer([redacted trust and pin])")
    }
}

impl ServerPeer {
    /// Creates mandatory client-chain validation inputs and pin.
    #[must_use]
    pub const fn new(trust: Vec<CertificateDer<'static>>, pin: [u8; 32]) -> Self {
        Self { trust, pin }
    }
}

/// Admission transcript and one absolute I/O budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TlsAdmission {
    pub(crate) binding: AdmissionBinding,
    pub(crate) budget: Duration,
}

impl TlsAdmission {
    /// Creates one admission configuration shared by all phases.
    #[must_use]
    pub const fn new(binding: AdmissionBinding, budget: Duration) -> Self {
        Self { binding, budget }
    }
}

/// Redacted pinned-TLS failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TlsError {
    /// TLS configuration is invalid.
    #[error("TLS configuration failed")]
    Configuration,
    /// Standard certificate processing failed.
    #[error("TLS certificate validation failed")]
    Certificate,
    /// TLS 1.3 was not negotiated.
    #[error("TLS version rejected")]
    Version,
    /// Exact SPKI pin did not match.
    #[error("TLS peer pin rejected")]
    Pin,
    /// Transcript-bound admission failed.
    #[error("TLS admission rejected")]
    Admission,
    /// Framing was empty or exceeded the fixed cap.
    #[error("TLS application frame rejected")]
    Frame,
    /// One absolute deadline expired.
    #[error("TLS deadline expired")]
    Deadline,
    /// Redacted socket or TLS I/O failure.
    #[error("TLS I/O failed")]
    Io,
}
