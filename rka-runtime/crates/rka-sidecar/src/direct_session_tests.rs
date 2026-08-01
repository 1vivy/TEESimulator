use std::{
    fmt::Write as _,
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
use rustls::pki_types::CertificateDer;

use super::{DirectSessionError, connect_bound};
use crate::{
    LifecycleRole,
    direct_profile::{DialMode, DirectProfile, load_from},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub(super) struct TempState(pub(super) PathBuf);

impl TempState {
    pub(super) fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
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

pub(super) fn routed_local_ipv4() -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
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

pub(super) fn persist_profile(
    root: &Path,
    profile: (LifecycleRole, Ipv4Addr, [u8; 32]),
) -> Result<DirectProfile, Box<dyn std::error::Error>> {
    let (role, listen_interface, peer_pin) = profile;
    let profile_path = root.join("profiles/direct.conf");
    fs::create_dir_all(root.join("profiles"))?;
    let role_line = match role {
        LifecycleRole::Donor => "DONOR",
        LifecycleRole::Candidate => "CANDIDATE",
    };
    let encoded_pin = peer_pin.iter().fold(String::new(), |mut encoded, byte| {
        let _ = write!(encoded, "{byte:02x}");
        encoded
    });
    fs::write(
        &profile_path,
        format!(
            "version=2\nrole={role_line}\nprofile_epoch=9\ndial_mode=DONOR_DIALS\ndial_endpoint={listen_interface}\nlisten_interface={listen_interface}\npeer_spki_sha256={encoded_pin}\ntransport=DIRECT\n"
        ),
    )?;
    let (profile, _) = load_from((root, &profile_path, role), 9)?;
    assert_eq!(profile.dial_mode, DialMode::DonorDials);
    Ok(profile)
}

pub(super) fn persist_identity(
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

pub(super) type Identities = (
    CertificateDer<'static>,
    CertificateDer<'static>,
    Vec<u8>,
    CertificateDer<'static>,
    Vec<u8>,
);

pub(super) fn identities() -> Result<Identities, Box<dyn std::error::Error>> {
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
