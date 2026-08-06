use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    path::Path,
    time::Duration,
};

use rka_state::PairedActivationRecord;
use rka_transport::{
    AdmissionBinding, ClientPeer, PinnedTlsCandidateServer, PinnedTlsDonorClient, ServerPeer,
    TlsAdmission, TlsCredentials, TlsError,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

use crate::{
    candidate::{AuthenticatedCandidateContext, PairingCatalog},
    direct_profile::DirectProfile,
    provisioning_io::FileStateStore,
};

mod candidate_role;
mod donor_binding;
mod donor_role;
mod runtime_paths;

pub use candidate_role::run_candidate;
pub use donor_role::{run_donor, run_donor_bridge};

#[cfg(test)]
use candidate_role::{CandidateIterationError, run_candidate_once};
use donor_binding::{DonorProfileBinding, resolve_donor_bindings};
#[cfg(test)]
use donor_role::{DonorIteration, run_donor_once};
#[cfg(test)]
use runtime_paths::candidate_diagnostic_path;
use runtime_paths::{bind_local, diagnostic, local_socket_path};
#[cfg(test)]
use runtime_paths::{candidate_diagnostic, candidate_local_socket_path};

const PORT: u16 = 37_373;
const BUDGET: Duration = Duration::from_secs(25);
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

fn tls_status(error: TlsError, phase: &str) -> String {
    let category = match error {
        TlsError::Configuration => "configuration",
        TlsError::Certificate => "certificate",
        TlsError::Version => "version",
        TlsError::Pin => "pin",
        TlsError::Admission => "admission",
        TlsError::Frame => "frame",
        TlsError::Deadline => "deadline",
        TlsError::Io => "io",
        _ => "unknown",
    };
    format!("{phase}_{category}")
}

fn donor_client(
    state: &Path,
    binding: &DonorProfileBinding,
) -> Result<PinnedTlsDonorClient<AuthenticatedCandidateContext>, DirectSessionError> {
    let (tls_admission, profile_id_hash) = admission(&binding.runtime_root, &binding.profile)?;
    if binding.authenticated.peer_spki_hash() != &binding.profile.peer_pin
        || binding.authenticated.profile_epoch() != binding.profile.epoch
        || binding.authenticated.profile_id_hash() != &profile_id_hash
    {
        return Err(DirectSessionError::State);
    }
    PinnedTlsDonorClient::new(
        identity(state)?,
        ClientPeer::new(
            peer_trust(state)?,
            ServerName::try_from("teesimulator-rka.local".to_owned())
                .map_err(|_| DirectSessionError::State)?,
            binding.profile.peer_pin,
        ),
        tls_admission,
        binding.authenticated,
    )
    .map_err(|_| DirectSessionError::Tls)
}

fn authenticated_profile(
    state: &Path,
    profile: &DirectProfile,
) -> Result<AuthenticatedCandidateContext, DirectSessionError> {
    PairingCatalog::load(state)
        .and_then(|catalog| catalog.lookup_profile(profile.peer_pin, profile.epoch))
        .map_err(|_| DirectSessionError::State)
}

fn candidate_server(
    state: &Path,
    profile: &DirectProfile,
) -> Result<PinnedTlsCandidateServer, DirectSessionError> {
    let (tls_admission, _) = admission(state, profile)?;
    let result = PinnedTlsCandidateServer::new(
        identity(state)?,
        &ServerPeer::new(peer_trust(state)?, profile.peer_pin),
        tls_admission,
    );
    if let Err(error) = &result {
        diagnostic(state, &tls_status(*error, "candidate_setup"));
    }
    result.map_err(|_| DirectSessionError::Tls)
}

fn admission(
    state: &Path,
    profile: &DirectProfile,
) -> Result<(TlsAdmission, [u8; 32]), DirectSessionError> {
    let record = PairedActivationRecord::load(&FileStateStore::new(state))
        .map_err(|_| DirectSessionError::State)?;
    if record.profile_epoch != profile.epoch || record.peer_spki_hash != profile.peer_pin {
        return Err(DirectSessionError::State);
    }
    Ok((
        TlsAdmission::new(
            AdmissionBinding::new([
                record.profile_id_hash,
                record.session_id,
                record.candidate_nonce,
                record.prior_transcript_hash,
            ]),
            BUDGET,
        ),
        record.profile_id_hash,
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
