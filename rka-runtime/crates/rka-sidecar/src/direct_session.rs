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
const LOCAL_BRIDGE_SOCKET: &str = "broker.sock";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DonorIteration {
    Served,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateIteration {
    accepted_connections: usize,
}

#[derive(Debug, Error)]
#[error("candidate iteration failed after {accepted_connections} accepted connections")]
struct CandidateIterationError {
    #[source]
    error: DirectSessionError,
    accepted_connections: usize,
}

#[doc(hidden)]
pub fn run_donor(runtime: &mut DonorRuntime) -> Result<(), DirectSessionError> {
    let (state, profile, _) =
        crate::direct_profile::load(LifecycleRole::Donor).map_err(|_| DirectSessionError::State)?;
    if profile.dial_mode != DialMode::DonorDials {
        return Err(DirectSessionError::State);
    }
    loop {
        match run_donor_once(
            (runtime, &state, &profile),
            SocketAddrV4::new(profile.endpoint, PORT),
        )? {
            DonorIteration::Served => {}
            DonorIteration::Retry => std::thread::sleep(Duration::from_secs(1)),
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
        run_candidate_once((&network, &local, &state, &profile))
            .map_err(|failure| failure.error)?;
    }
}

fn run_donor_once(
    context: (&mut DonorRuntime, &Path, &DirectProfile),
    remote: SocketAddrV4,
) -> Result<DonorIteration, DirectSessionError> {
    let (runtime, state, profile) = context;
    let Ok(socket) = connect_bound(profile.listen_interface, remote, BUDGET) else {
        return Ok(DonorIteration::Retry);
    };
    let donor = donor_client(state, profile)?;
    let dispatched = Cell::new(false);
    let result = donor.serve_once(socket, |request| {
        dispatched.set(true);
        runtime
            .dispatch_frame(request)
            .map_err(|_| rka_transport::TlsError::Admission)
    });
    match (result, dispatched.get()) {
        (Ok(()), _) => Ok(DonorIteration::Served),
        (Err(_), true) => Err(DirectSessionError::Ambiguous),
        (Err(_), false) => Ok(DonorIteration::Retry),
    }
}

fn run_candidate_once(
    context: (&TcpListener, &UnixListener, &Path, &DirectProfile),
) -> Result<CandidateIteration, CandidateIterationError> {
    let (network, local, state, profile) = context;
    let (mut broker, _) = local
        .accept()
        .map_err(|_| candidate_failure(DirectSessionError::Io, 0))?;
    let credentials =
        socket_peercred(&broker).map_err(|_| candidate_failure(DirectSessionError::State, 0))?;
    if credentials.uid != geteuid() {
        return Err(candidate_failure(DirectSessionError::State, 0));
    }
    let request = read_frame(&mut broker).map_err(|error| candidate_failure(error, 0))?;
    let exchange = exchange_candidate_request((network, state, profile), &request)?;
    write_frame(&mut broker, &exchange.response)
        .map_err(|error| candidate_failure(error, exchange.accepted_connections))?;
    Ok(CandidateIteration {
        accepted_connections: exchange.accepted_connections,
    })
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

struct CandidateExchange {
    response: Vec<u8>,
    accepted_connections: usize,
}

fn exchange_candidate_request(
    context: (&TcpListener, &Path, &DirectProfile),
    request: &[u8],
) -> Result<CandidateExchange, CandidateIterationError> {
    let (network, state, profile) = context;
    let candidate =
        candidate_server(state, profile).map_err(|error| candidate_failure(error, 0))?;
    for attempt in 0..PRE_DISPATCH_ATTEMPTS {
        let accepted_connections = attempt.saturating_add(1);
        let (socket, _) = network
            .accept()
            .map_err(|_| candidate_failure(DirectSessionError::Io, attempt))?;
        match candidate.exchange(socket, request) {
            Ok(response) => {
                return Ok(CandidateExchange {
                    response,
                    accepted_connections,
                });
            }
            Err(CandidateExchangeError::PreDispatch(_))
                if attempt < PRE_DISPATCH_ATTEMPTS.saturating_sub(1) => {}
            Err(CandidateExchangeError::Ambiguous(_)) => {
                return Err(candidate_failure(
                    DirectSessionError::Ambiguous,
                    accepted_connections,
                ));
            }
            Err(_) => {
                return Err(candidate_failure(
                    DirectSessionError::Tls,
                    accepted_connections,
                ));
            }
        }
    }
    Err(candidate_failure(
        DirectSessionError::Tls,
        PRE_DISPATCH_ATTEMPTS,
    ))
}

const fn candidate_failure(
    error: DirectSessionError,
    accepted_connections: usize,
) -> CandidateIterationError {
    CandidateIterationError {
        error,
        accepted_connections,
    }
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
    let path = directory.join(LOCAL_BRIDGE_SOCKET);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(DirectSessionError::Io),
    }
    let listener = UnixListener::bind(path).map_err(|_| DirectSessionError::Io)?;
    fs::set_permissions(
        directory.join(LOCAL_BRIDGE_SOCKET),
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

#[cfg(test)]
#[path = "direct_session_runner_tests.rs"]
mod runner_tests;
