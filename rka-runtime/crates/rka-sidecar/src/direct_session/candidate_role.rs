use std::{
    net::{SocketAddrV4, TcpListener},
    os::unix::net::UnixListener,
    path::Path,
};

use rka_transport::CandidateExchangeError;
use rustix::{net::sockopt::socket_peercred, process::geteuid};
use thiserror::Error;

use crate::{
    LifecycleRole,
    direct_profile::{DialMode, DirectProfile},
};

use super::{
    DirectSessionError, PORT, PRE_DISPATCH_ATTEMPTS, bind_local, candidate_server, diagnostic,
    read_frame, tls_status, write_frame,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CandidateIteration {
    pub(super) accepted_connections: usize,
}

#[derive(Debug, Error)]
#[error("candidate iteration failed after {accepted_connections} accepted connections")]
pub(super) struct CandidateIterationError {
    #[source]
    pub(super) error: DirectSessionError,
    pub(super) accepted_connections: usize,
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

pub(super) fn run_candidate_once(
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

struct CandidateExchange {
    response: Vec<u8>,
    accepted_connections: usize,
}

fn exchange_candidate_request(
    context: (&TcpListener, &Path, &DirectProfile),
    request: &[u8],
) -> Result<CandidateExchange, CandidateIterationError> {
    let (network, state, profile) = context;
    let candidate = candidate_server(state, profile).map_err(|error| {
        let status = match &error {
            DirectSessionError::State => "candidate_setup_state",
            DirectSessionError::Io => "candidate_setup_io",
            DirectSessionError::Tls => "candidate_setup_tls",
            DirectSessionError::Ambiguous => "candidate_setup_ambiguous",
        };
        diagnostic(state, status);
        candidate_failure(error, 0)
    })?;
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
            Err(CandidateExchangeError::PreDispatch(error))
                if attempt < PRE_DISPATCH_ATTEMPTS.saturating_sub(1) =>
            {
                diagnostic(state, &tls_status(error, "candidate_pre_dispatch"));
            }
            Err(CandidateExchangeError::Ambiguous(error)) => {
                diagnostic(state, &tls_status(error, "candidate_ambiguous"));
                return Err(candidate_failure(
                    DirectSessionError::Ambiguous,
                    accepted_connections,
                ));
            }
            Err(CandidateExchangeError::PreDispatch(error)) => {
                diagnostic(state, &tls_status(error, "candidate_pre_dispatch"));
                return Err(candidate_failure(
                    DirectSessionError::Tls,
                    accepted_connections,
                ));
            }
            Err(_) => {
                diagnostic(state, "candidate_pre_dispatch_unknown");
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
