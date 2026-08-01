use std::{net::IpAddr, time::Duration};

use crate::{
    DialMode, DirectEndpointProfile, DirectPath, DirectProfileInput, DirectProfileRotation,
    DirectReachability, DirectReadinessStatus, Endpoint, ProfileError, TransportKind,
    direct_profile::{DirectEvidenceInput, DirectPinnedTlsAdmission},
};

#[test]
fn endpoint_profile_selects_pinned_lan_and_tailscale_vectors()
-> Result<(), Box<dyn std::error::Error>> {
    let lan = profile(Vector::lan())?;
    let tailscale = profile(Vector::tailscale())?;

    assert_eq!(lan.connect_endpoint().host(), "192.168.50.8");
    assert_eq!(tailscale.connect_endpoint().host(), "100.88.0.8");
    assert_eq!(lan.listen_interface(), "192.168.50.9".parse::<IpAddr>()?);
    assert_eq!(tailscale.peer_spki(), [0x22; 32]);
    assert_eq!(tailscale.dial_mode(), DialMode::DonorDials);
    let profiles = vec![lan.clone(), tailscale.clone()];
    assert_eq!(
        DirectEndpointProfile::select(&profiles, DirectPath::Lan)?,
        &lan
    );
    assert_eq!(
        DirectEndpointProfile::select(&profiles, DirectPath::Tailscale)?,
        &tailscale
    );
    assert!(Endpoint::parse("192.168.050.8", 8443).is_err());
    assert_eq!(
        DirectEndpointProfile::parse(DirectProfileInput {
            epoch: 7,
            path: DirectPath::Lan,
            dial_mode: DialMode::CandidateDials,
            connect_endpoint: Endpoint::parse("192.168.50.8", 8443)?,
            listen_interface: "0.0.0.0".parse()?,
            peer_spki: [0x11; 32],
            connect_timeout: Duration::from_secs(2),
            listen_timeout: Duration::from_secs(3),
        }),
        Err(ProfileError::Direct)
    );
    assert_eq!(
        DirectEndpointProfile::parse(DirectProfileInput {
            epoch: 7,
            path: DirectPath::Lan,
            dial_mode: DialMode::CandidateDials,
            connect_endpoint: Endpoint::parse("192.168.50.8", 8443)?,
            listen_interface: "192.168.50.9".parse()?,
            peer_spki: [0x11; 32],
            connect_timeout: Duration::from_secs(31),
            listen_timeout: Duration::from_secs(3),
        }),
        Err(ProfileError::Direct)
    );
    Ok(())
}

#[test]
fn endpoint_profile_requires_exact_direct_pinned_tls_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let current = profile(Vector::lan())?;
    let exact = DirectReachability::trusted_direct_pinned_tls(evidence(&current));
    assert_eq!(
        current.readiness(&exact, false).status(),
        DirectReadinessStatus::DirectReady
    );

    for mutation in [
        DirectEvidenceInput {
            path: DirectPath::Tailscale,
            ..evidence(&current)
        },
        DirectEvidenceInput {
            connect_endpoint: Endpoint::parse("192.168.50.7", 8443)?,
            ..evidence(&current)
        },
        DirectEvidenceInput {
            listen_interface: "192.168.50.7".parse()?,
            ..evidence(&current)
        },
        DirectEvidenceInput {
            epoch: 6,
            ..evidence(&current)
        },
        DirectEvidenceInput {
            peer_spki: [0x12; 32],
            ..evidence(&current)
        },
        DirectEvidenceInput {
            transport: TransportKind::DiagnosticUsbRelay,
            ..evidence(&current)
        },
        DirectEvidenceInput {
            reciprocal_admission: None,
            ..evidence(&current)
        },
    ] {
        let result = DirectReachability::trusted_direct_pinned_tls(mutation);
        assert_eq!(
            current.readiness(&result, true).status(),
            DirectReadinessStatus::DirectNetworkBlocked
        );
        assert!(current.readiness(&result, true).usb_succeeded());
    }
    Ok(())
}

#[test]
fn endpoint_profile_rotation_rejects_stale_direct_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let current = profile(Vector::lan())?;
    let stale = DirectReachability::trusted_direct_pinned_tls(evidence(&current));
    let next = profile(Vector::next_lan())?;
    let mut rotation = DirectProfileRotation::new(current);
    rotation.prepare(next.clone())?;
    rotation.activate()?;

    assert_eq!(rotation.active(), &next);
    assert_eq!(
        rotation.active().readiness(&stale, true).status(),
        DirectReadinessStatus::DirectNetworkBlocked
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct Vector {
    epoch: u64,
    path: DirectPath,
    host: &'static str,
    listen_interface: &'static str,
    pin: u8,
    dial_mode: DialMode,
}

impl Vector {
    const fn lan() -> Self {
        Self {
            epoch: 7,
            path: DirectPath::Lan,
            host: "192.168.50.8",
            listen_interface: "192.168.50.9",
            pin: 0x11,
            dial_mode: DialMode::CandidateDials,
        }
    }

    const fn next_lan() -> Self {
        Self {
            epoch: 8,
            path: DirectPath::Lan,
            host: "192.168.50.10",
            listen_interface: "192.168.50.9",
            pin: 0x22,
            dial_mode: DialMode::CandidateDials,
        }
    }

    const fn tailscale() -> Self {
        Self {
            epoch: 8,
            path: DirectPath::Tailscale,
            host: "100.88.0.8",
            listen_interface: "100.88.0.9",
            pin: 0x22,
            dial_mode: DialMode::DonorDials,
        }
    }
}

fn profile(vector: Vector) -> Result<DirectEndpointProfile, ProfileError> {
    DirectEndpointProfile::parse(DirectProfileInput {
        epoch: vector.epoch,
        path: vector.path,
        dial_mode: vector.dial_mode,
        connect_endpoint: Endpoint::parse(vector.host, 8443)?,
        listen_interface: vector
            .listen_interface
            .parse()
            .map_err(|_| ProfileError::Direct)?,
        peer_spki: [vector.pin; 32],
        connect_timeout: Duration::from_secs(2),
        listen_timeout: Duration::from_secs(3),
    })
}

fn evidence(profile: &DirectEndpointProfile) -> DirectEvidenceInput {
    DirectEvidenceInput {
        path: profile.path(),
        dial_mode: profile.dial_mode(),
        connect_endpoint: profile.connect_endpoint().clone(),
        listen_interface: profile.listen_interface(),
        epoch: profile.epoch(),
        peer_spki: profile.peer_spki(),
        transport: TransportKind::DirectPinnedTls,
        reciprocal_admission: Some(DirectPinnedTlsAdmission::reciprocal()),
    }
}
