use std::{
    cell::Cell,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    time::Duration,
};

use rka_state::PairedActivationRecord;
use rka_transport::{
    AdmissionBinding, CandidateExchangeError, ClientPeer, PinnedTlsCandidateServer,
    PinnedTlsDonorClient, ServerPeer, TlsAdmission, TlsCredentials,
};
use rustix::{net::sockopt::socket_peercred, process::geteuid};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

use crate::{
    LifecycleRole,
    direct_profile::{DialMode, DirectProfile},
    donor::DonorRuntime,
    provisioning_io::FileStateStore,
};

const PORT: u16 = 37_373;
const BUDGET: Duration = Duration::from_secs(8);
const MAX_FRAME_BYTES: usize = 1_048_576;
const PRE_DISPATCH_ATTEMPTS: usize = 3;

#[derive(Debug, Error)]
#[doc(hidden)]
#[non_exhaustive]
pub enum DirectSessionError {
    #[error("direct session state rejected")]
    State,
    #[error("direct session I/O failed")]
    Io,
    #[error("direct session TLS rejected")]
    Tls,
    #[error("direct session request became ambiguous")]
    Ambiguous,
}

#[doc(hidden)]
pub fn run_donor(runtime: &mut DonorRuntime) -> Result<(), DirectSessionError> {
    let (state, profile, _) =
        crate::direct_profile::load(LifecycleRole::Donor).map_err(|_| DirectSessionError::State)?;
    if profile.dial_mode != DialMode::DonorDials {
        return Err(DirectSessionError::State);
    }
    loop {
        let Ok(socket) = connect_bound(
            profile.listen_interface,
            SocketAddrV4::new(profile.endpoint, PORT),
            BUDGET,
        ) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let donor = donor_client(&state, &profile)?;
        let dispatched = Cell::new(false);
        let result = donor.serve_once(socket, |request| {
            dispatched.set(true);
            runtime
                .dispatch_frame(request)
                .map_err(|_| rka_transport::TlsError::Admission)
        });
        if result.is_err() && dispatched.get() {
            return Err(DirectSessionError::Ambiguous);
        }
        if result.is_err() {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

#[doc(hidden)]
pub fn run_candidate() -> Result<(), DirectSessionError> {
    let (state, profile, _) = crate::direct_profile::load(LifecycleRole::Candidate)
        .map_err(|_| DirectSessionError::State)?;
    if profile.dial_mode != DialMode::DonorDials {
        return Err(DirectSessionError::State);
    }
    let network = TcpListener::bind(SocketAddrV4::new(profile.listen_interface, PORT))
        .map_err(|_| DirectSessionError::Io)?;
    let local = bind_local(&state)?;
    loop {
        let (mut broker, _) = local.accept().map_err(|_| DirectSessionError::Io)?;
        let credentials = socket_peercred(&broker).map_err(|_| DirectSessionError::State)?;
        if credentials.uid != geteuid() {
            return Err(DirectSessionError::State);
        }
        let request = read_frame(&mut broker)?;
        let response = exchange_candidate_request((&network, &state, &profile), &request)?;
        write_frame(&mut broker, &response)?;
    }
}

fn connect_bound(
    local: Ipv4Addr,
    remote: SocketAddrV4,
    budget: Duration,
) -> Result<TcpStream, DirectSessionError> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| DirectSessionError::Io)?;
    socket
        .bind(&SockAddr::from(SocketAddrV4::new(local, 0)))
        .map_err(|_| DirectSessionError::Io)?;
    socket
        .connect_timeout(&SockAddr::from(remote), budget)
        .map_err(|_| DirectSessionError::Io)?;
    let stream = TcpStream::from(socket);
    match stream.local_addr().map_err(|_| DirectSessionError::Io)? {
        SocketAddr::V4(bound) if *bound.ip() == local => Ok(stream),
        SocketAddr::V4(_) | SocketAddr::V6(_) => Err(DirectSessionError::Io),
    }
}

fn exchange_candidate_request(
    context: (&TcpListener, &Path, &DirectProfile),
    request: &[u8],
) -> Result<Vec<u8>, DirectSessionError> {
    let (network, state, profile) = context;
    let candidate = candidate_server(state, profile)?;
    for attempt in 0..PRE_DISPATCH_ATTEMPTS {
        let (socket, _) = network.accept().map_err(|_| DirectSessionError::Io)?;
        match candidate.exchange(socket, request) {
            Ok(response) => return Ok(response),
            Err(CandidateExchangeError::PreDispatch(_))
                if attempt < PRE_DISPATCH_ATTEMPTS.saturating_sub(1) => {}
            Err(CandidateExchangeError::Ambiguous(_)) => {
                return Err(DirectSessionError::Ambiguous);
            }
            Err(_) => return Err(DirectSessionError::Tls),
        }
    }
    Err(DirectSessionError::Tls)
}

fn donor_client(
    state: &Path,
    profile: &DirectProfile,
) -> Result<PinnedTlsDonorClient, DirectSessionError> {
    PinnedTlsDonorClient::new(
        identity(state)?,
        ClientPeer::new(
            peer_trust(state)?,
            ServerName::try_from("teesimulator-rka.local".to_owned())
                .map_err(|_| DirectSessionError::State)?,
            profile.peer_pin,
        ),
        admission(state, profile)?,
    )
    .map_err(|_| DirectSessionError::Tls)
}

fn candidate_server(
    state: &Path,
    profile: &DirectProfile,
) -> Result<PinnedTlsCandidateServer, DirectSessionError> {
    PinnedTlsCandidateServer::new(
        identity(state)?,
        &ServerPeer::new(peer_trust(state)?, profile.peer_pin),
        admission(state, profile)?,
    )
    .map_err(|_| DirectSessionError::Tls)
}

fn admission(state: &Path, profile: &DirectProfile) -> Result<TlsAdmission, DirectSessionError> {
    let record = PairedActivationRecord::load(&FileStateStore::new(state))
        .map_err(|_| DirectSessionError::State)?;
    if record.profile_epoch != profile.epoch || record.peer_spki_hash != profile.peer_pin {
        return Err(DirectSessionError::State);
    }
    Ok(TlsAdmission::new(
        AdmissionBinding::new([
            record.profile_id_hash,
            record.session_id,
            record.candidate_nonce,
            record.prior_transcript_hash,
        ]),
        BUDGET,
    ))
}

fn identity(state: &Path) -> Result<TlsCredentials, DirectSessionError> {
    let certificate = pem::parse(
        fs::read(state.join("trust/transport-self.pem")).map_err(|_| DirectSessionError::State)?,
    )
    .map_err(|_| DirectSessionError::State)?;
    let key = pem::parse(
        fs::read(state.join("secrets/transport.key")).map_err(|_| DirectSessionError::State)?,
    )
    .map_err(|_| DirectSessionError::State)?;
    if certificate.tag() != "CERTIFICATE" || key.tag() != "PRIVATE KEY" {
        return Err(DirectSessionError::State);
    }
    Ok(TlsCredentials::new(
        vec![CertificateDer::from(certificate.into_contents())],
        PrivatePkcs8KeyDer::from(key.into_contents()).into(),
    ))
}

fn peer_trust(state: &Path) -> Result<Vec<CertificateDer<'static>>, DirectSessionError> {
    let certificate = pem::parse(
        fs::read(state.join("trust/transport-peer.pem")).map_err(|_| DirectSessionError::State)?,
    )
    .map_err(|_| DirectSessionError::State)?;
    if certificate.tag() != "CERTIFICATE" {
        return Err(DirectSessionError::State);
    }
    Ok(vec![CertificateDer::from(certificate.into_contents())])
}

fn bind_local(state: &Path) -> Result<UnixListener, DirectSessionError> {
    let directory = state.join("run/sockets");
    fs::create_dir_all(&directory).map_err(|_| DirectSessionError::Io)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| DirectSessionError::Io)?;
    let path = directory.join("candidate-rka.sock");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(DirectSessionError::Io),
    }
    let listener = UnixListener::bind(path).map_err(|_| DirectSessionError::Io)?;
    fs::set_permissions(
        directory.join("candidate-rka.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| DirectSessionError::Io)?;
    Ok(listener)
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, DirectSessionError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| DirectSessionError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| DirectSessionError::Io)?;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(DirectSessionError::State);
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|_| DirectSessionError::Io)?;
    Ok(frame)
}

fn write_frame(stream: &mut impl Write, response: &[u8]) -> Result<(), DirectSessionError> {
    let length = u32::try_from(response.len()).map_err(|_| DirectSessionError::State)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(response))
        .map_err(|_| DirectSessionError::Io)
}

#[cfg(test)]
#[path = "direct_session_tests.rs"]
mod tests;
