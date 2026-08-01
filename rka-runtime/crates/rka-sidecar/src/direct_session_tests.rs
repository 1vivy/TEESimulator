use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rka_state::PairedActivationRecord;
use rka_transport::peer_spki_hash;
use rustls::pki_types::CertificateDer;

use super::{
    DirectSessionError, candidate_server, connect_bound, donor_client, exchange_candidate_request,
};
use crate::{
    direct_profile::{DialMode, DirectProfile},
    provisioning_io::FileStateStore,
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempState(PathBuf);

impl TempState {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("rka-direct-{label}-{}-{id}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn routed_local_ipv4() -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_unspecified() => Ok(address),
        _ => Err("IPv4 route unavailable".into()),
    }
}

#[test]
fn donor_connector_binds_the_exact_profile_source() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let local = routed_local_ipv4()?;
    let listener = TcpListener::bind(SocketAddrV4::new(local, 0))?;
    let remote = match listener.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => return Err("unexpected IPv6 listener".into()),
    };

    // When
    let stream = connect_bound(local, remote, Duration::from_secs(1))?;

    // Then
    assert_eq!(stream.local_addr()?.ip(), local);
    Ok(())
}

#[test]
fn unavailable_profile_source_fails_before_connect() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let local = routed_local_ipv4()?;
    let listener = TcpListener::bind(SocketAddrV4::new(local, 0))?;
    listener.set_nonblocking(true)?;
    let remote = match listener.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => return Err("unexpected IPv6 listener".into()),
    };

    // When
    let result = connect_bound(
        Ipv4Addr::new(192, 0, 2, 254),
        remote,
        Duration::from_millis(100),
    );

    // Then
    assert!(matches!(result, Err(DirectSessionError::Io)));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[test]
fn production_direct_session_uses_persisted_admission_and_donor_dial_direction()
-> Result<(), Box<dyn std::error::Error>> {
    // Given: independently persisted donor and candidate session-manager state.
    let local = routed_local_ipv4()?;
    let donor_state = TempState::new("donor")?;
    let candidate_state = TempState::new("candidate")?;
    let (root_certificate, donor_certificate, donor_key, candidate_certificate, candidate_key) =
        identities()?;
    let donor_pin = peer_spki_hash(&donor_certificate)?;
    let candidate_pin = peer_spki_hash(&candidate_certificate)?;
    persist_identity(
        &donor_state.0,
        (&donor_certificate, &donor_key, &root_certificate),
    )?;
    persist_identity(
        &candidate_state.0,
        (&candidate_certificate, &candidate_key, &root_certificate),
    )?;
    persist_pairing(&donor_state.0, candidate_pin)?;
    persist_pairing(&candidate_state.0, donor_pin)?;
    let donor_profile = profile(local, candidate_pin);
    let candidate_profile = profile(local, donor_pin);
    let _candidate = candidate_server(&candidate_state.0, &candidate_profile)?;
    let _donor = donor_client(&donor_state.0, &donor_profile)?;
    let listener = TcpListener::bind(SocketAddrV4::new(local, 0))?;
    let remote = match listener.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => return Err("unexpected IPv6 listener".into()),
    };
    let candidate_root = candidate_state.0.clone();
    let worker = std::thread::spawn(move || {
        exchange_candidate_request(
            (&listener, &candidate_root, &candidate_profile),
            b"session-manager-request",
        )
    });

    // When: the donor creates the only TCP connection and dispatches the request.
    let socket = connect_bound(local, remote, Duration::from_secs(2))?;
    assert_eq!(socket.local_addr()?.ip(), local);
    donor_client(&donor_state.0, &donor_profile)?.serve_once(socket, |request| {
        assert_eq!(request, b"session-manager-request");
        Ok(b"session-manager-response".to_vec())
    })?;

    // Then: the candidate receives the response through the production exchange path.
    assert_eq!(
        worker.join().map_err(|_| "candidate thread failed")??,
        b"session-manager-response"
    );
    Ok(())
}

fn profile(listen_interface: Ipv4Addr, peer_pin: [u8; 32]) -> DirectProfile {
    DirectProfile {
        epoch: 9,
        endpoint: listen_interface,
        listen_interface,
        dial_mode: DialMode::DonorDials,
        peer_pin,
    }
}

fn persist_pairing(
    root: &Path,
    peer_spki_hash: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    PairedActivationRecord {
        peer_spki_hash,
        profile_id_hash: [0x11; 32],
        profile_epoch: 9,
        candidate_identity_hash: [0x22; 32],
        session_id: [0x33; 32],
        candidate_nonce: [0x44; 32],
        donor_nonce: [0x55; 32],
        prior_transcript_hash: [0x66; 32],
    }
    .persist(&FileStateStore::new(root))?;
    Ok(())
}

fn persist_identity(
    root: &Path,
    material: (&CertificateDer<'_>, &[u8], &CertificateDer<'_>),
) -> Result<(), Box<dyn std::error::Error>> {
    let (certificate, key, peer) = material;
    fs::create_dir_all(root.join("trust"))?;
    fs::create_dir_all(root.join("secrets"))?;
    fs::write(
        root.join("trust/transport-self.pem"),
        pem::encode(&pem::Pem::new("CERTIFICATE", certificate.as_ref())),
    )?;
    fs::write(
        root.join("trust/transport-peer.pem"),
        pem::encode(&pem::Pem::new("CERTIFICATE", peer.as_ref())),
    )?;
    fs::write(
        root.join("secrets/transport.key"),
        pem::encode(&pem::Pem::new("PRIVATE KEY", key)),
    )?;
    Ok(())
}

type Identities = (
    CertificateDer<'static>,
    CertificateDer<'static>,
    Vec<u8>,
    CertificateDer<'static>,
    Vec<u8>,
);

fn identities() -> Result<Identities, Box<dyn std::error::Error>> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_certificate = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let (candidate_certificate, candidate_key) = leaf(&issuer, true)?;
    let (donor_certificate, donor_key) = leaf(&issuer, false)?;
    Ok((
        ca_certificate.der().clone(),
        donor_certificate,
        donor_key,
        candidate_certificate,
        candidate_key,
    ))
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
    server: bool,
) -> Result<(CertificateDer<'static>, Vec<u8>), Box<dyn std::error::Error>> {
    let names = if server {
        vec!["teesimulator-rka.local".to_owned()]
    } else {
        vec!["donor.invalid".to_owned()]
    };
    let mut params = CertificateParams::new(names)?;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    });
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, issuer)?;
    Ok((certificate.der().clone(), key.serialize_der()))
}
