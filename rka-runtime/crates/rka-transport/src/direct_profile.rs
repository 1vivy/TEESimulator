use std::{net::IpAddr, time::Duration};

use crate::{Endpoint, ProfileError, TransportKind};

const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit approved direct path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectPath {
    /// Configured local-area network path.
    Lan,
    /// Configured Tailscale network path.
    Tailscale,
}

/// Parsed direct endpoint profile input.
#[derive(Debug)]
#[non_exhaustive]
pub struct DirectProfileInput {
    /// Strictly positive profile epoch.
    pub epoch: u64,
    /// Selected direct path.
    pub path: DirectPath,
    /// Exact remote connect endpoint.
    pub connect_endpoint: Endpoint,
    /// Exact local non-wildcard listener interface.
    pub listen_interface: IpAddr,
    /// Exact peer SPKI pin.
    pub peer_spki: [u8; 32],
    /// Bounded connect timeout.
    pub connect_timeout: Duration,
    /// Bounded listener setup timeout.
    pub listen_timeout: Duration,
}

/// Validated, explicit direct endpoint profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectEndpointProfile {
    epoch: u64,
    path: DirectPath,
    connect_endpoint: Endpoint,
    listen_interface: IpAddr,
    peer_spki: [u8; 32],
    connect_timeout: Duration,
    listen_timeout: Duration,
}

impl DirectEndpointProfile {
    /// Validates direct path, endpoint, interface, pin, epoch, and timeouts.
    pub fn parse(input: DirectProfileInput) -> Result<Self, ProfileError> {
        if input.epoch == 0
            || input.listen_interface.is_unspecified()
            || !bounded(input.connect_timeout)
            || !bounded(input.listen_timeout)
        {
            return Err(ProfileError::Direct);
        }
        Ok(Self {
            epoch: input.epoch,
            path: input.path,
            connect_endpoint: input.connect_endpoint,
            listen_interface: input.listen_interface,
            peer_spki: input.peer_spki,
            connect_timeout: input.connect_timeout,
            listen_timeout: input.listen_timeout,
        })
    }

    /// Returns the profile epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the selected path.
    #[must_use]
    pub const fn path(&self) -> DirectPath {
        self.path
    }

    /// Returns the exact remote endpoint.
    #[must_use]
    pub const fn connect_endpoint(&self) -> &Endpoint {
        &self.connect_endpoint
    }

    /// Returns the exact local listener interface.
    #[must_use]
    pub const fn listen_interface(&self) -> IpAddr {
        self.listen_interface
    }

    /// Returns the exact peer pin.
    #[must_use]
    pub const fn peer_spki(&self) -> [u8; 32] {
        self.peer_spki
    }

    /// Returns the bounded connect timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the bounded listener timeout.
    #[must_use]
    pub const fn listen_timeout(&self) -> Duration {
        self.listen_timeout
    }

    /// Selects the only newest profile for a path.
    pub fn select(profiles: &[Self], path: DirectPath) -> Result<&Self, ProfileError> {
        let mut selected = None;
        for profile in profiles {
            if profile.path != path {
                continue;
            }
            selected = match selected {
                None => Some(profile),
                Some(current) if profile.epoch > current.epoch => Some(profile),
                Some(current) if profile.epoch == current.epoch => {
                    return Err(ProfileError::Direct);
                }
                Some(current) => Some(current),
            };
        }
        selected.ok_or(ProfileError::Direct)
    }

    /// Evaluates closed direct TLS evidence without promoting USB diagnostics.
    #[must_use]
    pub fn readiness(
        &self,
        reachability: &DirectReachability,
        usb_succeeded: bool,
    ) -> DirectReadiness {
        let evidence = reachability.evidence.as_ref();
        let ready = evidence.is_some_and(|value| {
            value.path == self.path
                && value.connect_endpoint == self.connect_endpoint
                && value.listen_interface == self.listen_interface
                && value.epoch == self.epoch
                && value.peer_spki == self.peer_spki
                && value.transport == TransportKind::DirectPinnedTls
        });
        DirectReadiness {
            status: if ready {
                DirectReadinessStatus::DirectReady
            } else {
                DirectReadinessStatus::DirectNetworkBlocked
            },
            usb_succeeded,
        }
    }
}

/// Closed production direct readiness status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectReadinessStatus {
    /// Exact direct pinned-TLS evidence matched the profile.
    DirectReady,
    /// Direct transport is unavailable or evidence is incomplete or stale.
    DirectNetworkBlocked,
}

/// Direct readiness plus diagnostic-only USB result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectReadiness {
    status: DirectReadinessStatus,
    usb_succeeded: bool,
}

impl DirectReadiness {
    /// Returns the closed direct readiness status.
    #[must_use]
    pub const fn status(&self) -> DirectReadinessStatus {
        self.status
    }

    /// Returns USB diagnostic success without granting direct readiness.
    #[must_use]
    pub const fn usb_succeeded(&self) -> bool {
        self.usb_succeeded
    }
}

/// Opaque reciprocal admission proof created only by pinned TLS.
#[derive(Clone, Copy, Debug)]
pub struct DirectPinnedTlsAdmission(());

impl DirectPinnedTlsAdmission {
    #[cfg(test)]
    pub(crate) const fn reciprocal() -> Self {
        Self(())
    }
}

/// Complete observed direct TLS evidence submitted to the trusted factory.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DirectEvidenceInput {
    /// Observed selected direct path.
    pub path: DirectPath,
    /// Observed remote endpoint.
    pub connect_endpoint: Endpoint,
    /// Observed local listener interface.
    pub listen_interface: IpAddr,
    /// Observed profile epoch.
    pub epoch: u64,
    /// Observed peer pin.
    pub peer_spki: [u8; 32],
    /// Observed transport kind.
    pub transport: TransportKind,
    /// Opaque reciprocal pinned-TLS admission proof.
    pub reciprocal_admission: Option<DirectPinnedTlsAdmission>,
}

#[derive(Clone, Debug)]
struct DirectEvidence {
    path: DirectPath,
    connect_endpoint: Endpoint,
    listen_interface: IpAddr,
    epoch: u64,
    peer_spki: [u8; 32],
    transport: TransportKind,
}

/// Opaque direct reachability evidence.
#[derive(Clone, Debug)]
pub struct DirectReachability {
    evidence: Option<DirectEvidence>,
}

impl DirectReachability {
    /// Returns evidence that cannot satisfy direct readiness.
    #[must_use]
    pub const fn unreachable() -> Self {
        Self { evidence: None }
    }

    /// Accepts only complete reciprocal direct pinned-TLS evidence.
    pub fn trusted_direct_pinned_tls(input: DirectEvidenceInput) -> Self {
        if input.transport != TransportKind::DirectPinnedTls || input.reciprocal_admission.is_none()
        {
            return Self::unreachable();
        }
        Self {
            evidence: Some(DirectEvidence {
                path: input.path,
                connect_endpoint: input.connect_endpoint,
                listen_interface: input.listen_interface,
                epoch: input.epoch,
                peer_spki: input.peer_spki,
                transport: input.transport,
            }),
        }
    }
}

/// Prepare-then-activate direct profile rotation state.
#[derive(Debug)]
pub struct DirectProfileRotation {
    active: DirectEndpointProfile,
    prepared: Option<DirectEndpointProfile>,
}

impl DirectProfileRotation {
    /// Creates direct rotation state.
    #[must_use]
    pub const fn new(active: DirectEndpointProfile) -> Self {
        Self {
            active,
            prepared: None,
        }
    }

    /// Returns the active direct profile.
    #[must_use]
    pub const fn active(&self) -> &DirectEndpointProfile {
        &self.active
    }

    /// Prepares a newer same-path profile with a changed pin.
    pub fn prepare(&mut self, next: DirectEndpointProfile) -> Result<(), ProfileError> {
        if next.path != self.active.path
            || next.epoch <= self.active.epoch
            || next.peer_spki == self.active.peer_spki
        {
            return Err(ProfileError::Direct);
        }
        self.prepared = Some(next);
        Ok(())
    }

    /// Activates the prepared profile.
    pub fn activate(&mut self) -> Result<(), ProfileError> {
        self.active = self.prepared.take().ok_or(ProfileError::Direct)?;
        Ok(())
    }
}

fn bounded(timeout: Duration) -> bool {
    !timeout.is_zero() && timeout <= MAX_TIMEOUT
}
