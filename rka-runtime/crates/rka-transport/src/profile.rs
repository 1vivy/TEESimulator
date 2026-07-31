use std::{fmt, net::IpAddr};

use rustls::pki_types::CertificateDer;
use thiserror::Error;

use crate::{SessionLifecycle, profile_id::profile_id};

const MAX_ALLOWED_IDENTITIES: usize = 16;
const MAX_TRUST_CERTIFICATES: usize = 8;
const MAX_CERTIFICATE_BYTES: usize = 65_536;

/// Fixed endpoint role in one paired profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Role {
    /// Candidate initiates the direct session.
    Candidate,
    /// Donor accepts and serves the direct session.
    Donor,
}

/// Transport kinds are disjoint capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportKind {
    /// Production, mutually authenticated pinned TLS.
    DirectPinnedTls,
    /// Diagnostic USB relay that can never satisfy direct readiness.
    DiagnosticUsbRelay,
}

impl TransportKind {
    /// Returns whether this kind can satisfy production readiness.
    #[must_use]
    pub const fn satisfies_direct(self) -> bool {
        match self {
            Self::DirectPinnedTls => true,
            Self::DiagnosticUsbRelay => false,
        }
    }

    pub(crate) const fn tag(self) -> u64 {
        match self {
            Self::DirectPinnedTls => 1,
            Self::DiagnosticUsbRelay => 2,
        }
    }
}

/// Canonical DNS/IP host and nonzero port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// Parses a canonical lowercase DNS name or RFC5952 IP literal.
    pub fn parse(host: &str, port: u16) -> Result<Self, ProfileError> {
        if port == 0 || host.is_empty() || host.len() > 253 {
            return Err(ProfileError::Endpoint);
        }
        let canonical = match host.parse::<IpAddr>() {
            Ok(address) => address.to_string(),
            Err(_) if valid_dns(host) && !looks_like_ipv4(host) => host.to_owned(),
            Err(_) => return Err(ProfileError::Endpoint),
        };
        if canonical != host {
            return Err(ProfileError::Endpoint);
        }
        Ok(Self {
            host: canonical,
            port,
        })
    }

    /// Returns the canonical host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the endpoint port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Validated public profile consumed by one exact role.
#[derive(Clone)]
pub struct PairedProfile {
    epoch: u64,
    local_role: Role,
    transport: TransportKind,
    endpoint: Endpoint,
    local_spki: [u8; 32],
    peer_spki: [u8; 32],
    peer_trust: Vec<CertificateDer<'static>>,
    allowed_identities: Vec<[u8; 32]>,
    root_hash: [u8; 32],
    policy_version: u64,
    id: [u8; 32],
}

impl fmt::Debug for PairedProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedProfile")
            .field("epoch", &self.epoch)
            .field("role", &self.local_role)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// Fully parsed profile input.
#[non_exhaustive]
pub struct ProfileInput {
    /// Strictly nonzero profile epoch.
    pub epoch: u64,
    /// Role of this local runtime.
    pub local_role: Role,
    /// Selected disjoint transport kind.
    pub transport: TransportKind,
    /// Donor endpoint.
    pub endpoint: Endpoint,
    /// Local transport SPKI pin.
    pub local_spki: [u8; 32],
    /// Peer transport SPKI pin.
    pub peer_spki: [u8; 32],
    /// Exact peer trust certificates.
    pub peer_trust: Vec<CertificateDer<'static>>,
    /// Sorted allowed candidate identities.
    pub allowed_identities: Vec<[u8; 32]>,
    /// Attestation root bundle hash.
    pub root_hash: [u8; 32],
    /// Frozen policy binding.
    pub policy_version: u64,
}

impl fmt::Debug for ProfileInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileInput([redacted profile material])")
    }
}

impl PairedProfile {
    /// Validates every public field and computes the frozen profile hash.
    pub fn parse(input: ProfileInput) -> Result<Self, ProfileError> {
        if input.epoch == 0
            || input.policy_version != 1
            || input.peer_trust.is_empty()
            || input.peer_trust.len() > MAX_TRUST_CERTIFICATES
            || input
                .peer_trust
                .iter()
                .any(|cert| cert.is_empty() || cert.len() > MAX_CERTIFICATE_BYTES)
            || input.allowed_identities.len() > MAX_ALLOWED_IDENTITIES
            || !strictly_sorted(&input.allowed_identities)
        {
            return Err(ProfileError::Invalid);
        }
        let id = profile_id(&input);
        Ok(Self {
            epoch: input.epoch,
            local_role: input.local_role,
            transport: input.transport,
            endpoint: input.endpoint,
            local_spki: input.local_spki,
            peer_spki: input.peer_spki,
            peer_trust: input.peer_trust,
            allowed_identities: input.allowed_identities,
            root_hash: input.root_hash,
            policy_version: input.policy_version,
            id,
        })
    }

    /// Returns the profile epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the exact peer pin.
    #[must_use]
    pub const fn peer_spki(&self) -> [u8; 32] {
        self.peer_spki
    }

    /// Returns the deterministic profile identifier.
    #[must_use]
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Returns the selected transport kind.
    #[must_use]
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    /// Returns the local role.
    #[must_use]
    pub const fn local_role(&self) -> Role {
        self.local_role
    }

    /// Returns the validated endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns exact peer trust material.
    #[must_use]
    pub fn peer_trust(&self) -> &[CertificateDer<'static>] {
        &self.peer_trust
    }

    /// Returns the exact local pin.
    #[must_use]
    pub const fn local_spki(&self) -> [u8; 32] {
        self.local_spki
    }

    /// Returns sorted allowed identity hashes.
    #[must_use]
    pub fn allowed_identities(&self) -> &[[u8; 32]] {
        &self.allowed_identities
    }

    /// Returns the attestation root-bundle hash.
    #[must_use]
    pub const fn root_hash(&self) -> [u8; 32] {
        self.root_hash
    }

    /// Returns the frozen policy binding.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }
}

/// Prepare-then-activate profile rotation state.
#[derive(Debug)]
pub struct ProfileRotation {
    active: PairedProfile,
    prepared: Option<PairedProfile>,
    lifecycle: SessionLifecycle,
}

impl ProfileRotation {
    /// Creates rotation state around one validated profile.
    #[must_use]
    pub const fn new(active: PairedProfile, lifecycle: SessionLifecycle) -> Self {
        Self {
            active,
            prepared: None,
            lifecycle,
        }
    }

    /// Prepares only a strictly newer, fully changed trust profile.
    pub fn prepare(&mut self, next: PairedProfile) -> Result<(), ProfileError> {
        if next.epoch <= self.active.epoch
            || next.peer_spki == self.active.peer_spki
            || next.peer_trust == self.active.peer_trust
        {
            return Err(ProfileError::Rotation);
        }
        self.prepared = Some(next);
        self.lifecycle.start_draining();
        Ok(())
    }

    /// Activates only after all old sessions are drained.
    pub fn activate(&mut self) -> Result<(), ProfileError> {
        if self.lifecycle.has_live_sessions() {
            return Err(ProfileError::SessionsLive);
        }
        self.active = self.prepared.take().ok_or(ProfileError::Rotation)?;
        self.lifecycle.finish_rotation();
        Ok(())
    }
}

/// Public-profile validation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProfileError {
    /// Endpoint is not canonical or bounded.
    #[error("profile endpoint is invalid")]
    Endpoint,
    /// A public profile field violates the frozen schema.
    #[error("public profile is invalid")]
    Invalid,
    /// Rotation does not strictly replace an older profile.
    #[error("profile rotation is invalid")]
    Rotation,
    /// Rotation cannot activate while a session is live.
    #[error("profile sessions are still live")]
    SessionsLive,
    /// A direct profile field or closed direct evidence is invalid.
    #[error("direct endpoint profile is invalid")]
    Direct,
}

fn valid_dns(host: &str) -> bool {
    host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) && host
        .split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

fn looks_like_ipv4(host: &str) -> bool {
    host.split('.').count() == 4
        && host
            .split('.')
            .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
}

fn strictly_sorted(values: &[[u8; 32]]) -> bool {
    values.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left < right)
    })
}
