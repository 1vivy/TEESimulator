use std::{
    cell::Cell,
    net::SocketAddrV4,
    path::Path,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};

use crate::{
    candidate::{AuthenticatedCandidateContext, CandidateId},
    direct_profile::{DialMode, DirectProfile},
    donor::{DonorRuntime, actor::CandidateActor},
};

use super::{
    BUDGET, DirectSessionError, PORT, authenticated_profile, candidate_diagnostic, connect_bound,
    donor_client,
};

mod bridge;

pub use bridge::run_donor_bridge;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DonorIteration {
    Served,
    Retry,
}

#[doc(hidden)]
pub fn run_donor(runtime: DonorRuntime) -> Result<(), DirectSessionError> {
    let (state, profiles) =
        crate::direct_profile::load_donor_profiles().map_err(|_| DirectSessionError::State)?;
    let runtime_actor = runtime_actor(runtime)?;
    let (failures, receiver) = mpsc::sync_channel(1);
    for (profile, _) in profiles {
        if profile.dial_mode != DialMode::DonorDials {
            return Err(DirectSessionError::State);
        }
        let authenticated = authenticated_profile(&state, &profile)?;
        let candidate = *authenticated.candidate();
        let runtime_actor = runtime_actor.clone();
        let actor = CandidateActor::spawn(candidate, move |frame: ActorFrame| {
            let (response, result) = mpsc::sync_channel(1);
            runtime_actor
                .send(RuntimeRequest { frame, response })
                .map_err(|_| crate::donor::DonorError::Broker)?;
            result
                .recv()
                .map_err(|_| crate::donor::DonorError::Broker)?
        })
        .map_err(|_| DirectSessionError::State)?;
        let state = state.clone();
        let failures = failures.clone();
        std::thread::Builder::new()
            .name("rka-profile-supervisor".to_owned())
            .spawn(move || {
                let result = run_profile_supervisor((&actor, &state, &profile), &candidate);
                let _ = failures.send(result);
            })
            .map_err(|_| DirectSessionError::State)?;
    }
    drop(failures);
    receiver.recv().map_err(|_| DirectSessionError::State)?
}

type ActorFrame = (AuthenticatedCandidateContext, Vec<u8>);

struct RuntimeRequest {
    frame: ActorFrame,
    response: SyncSender<Result<Vec<u8>, crate::donor::DonorError>>,
}

fn runtime_actor(
    mut runtime: DonorRuntime,
) -> Result<SyncSender<RuntimeRequest>, DirectSessionError> {
    let (sender, receiver) = mpsc::sync_channel::<RuntimeRequest>(32);
    std::thread::Builder::new()
        .name("rka-donor-runtime".to_owned())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                let (authenticated, frame) = request.frame;
                let result = runtime.dispatch(&authenticated, &frame);
                if request.response.send(result).is_err() {
                    break;
                }
            }
        })
        .map_err(|_| DirectSessionError::State)?;
    Ok(sender)
}

fn run_profile_supervisor(
    context: (&CandidateActor<ActorFrame>, &Path, &DirectProfile),
    candidate: &CandidateId,
) -> Result<(), DirectSessionError> {
    let (actor, state, profile) = context;
    loop {
        match run_donor_actor_once(
            (actor, state, profile),
            SocketAddrV4::new(profile.endpoint, PORT),
        )? {
            DonorIteration::Served => {}
            DonorIteration::Retry => {
                candidate_diagnostic(state, candidate, "donor_pre_dispatch");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn run_donor_actor_once(
    context: (&CandidateActor<ActorFrame>, &Path, &DirectProfile),
    remote: SocketAddrV4,
) -> Result<DonorIteration, DirectSessionError> {
    let (actor, state, profile) = context;
    let donor = donor_client(state, profile)?;
    let Ok(socket) = connect_bound(profile.listen_interface, remote, BUDGET) else {
        return Ok(DonorIteration::Retry);
    };
    let dispatched = Cell::new(false);
    let result = donor.serve_once(socket, |authenticated, request| {
        dispatched.set(true);
        actor
            .dispatch(
                authenticated.candidate(),
                (*authenticated, request.to_vec()),
            )
            .map_err(|_| rka_transport::TlsError::Admission)
    });
    match (result, dispatched.get()) {
        (Ok(()), _) => Ok(DonorIteration::Served),
        (Err(_), true) => Err(DirectSessionError::Ambiguous),
        (Err(_), false) => Ok(DonorIteration::Retry),
    }
}

#[cfg(test)]
pub(super) fn run_donor_once(
    context: (&mut DonorRuntime, &Path, &DirectProfile),
    remote: SocketAddrV4,
) -> Result<DonorIteration, DirectSessionError> {
    let (runtime, state, profile) = context;
    let donor = donor_client(state, profile)?;
    let Ok(socket) = connect_bound(profile.listen_interface, remote, BUDGET) else {
        return Ok(DonorIteration::Retry);
    };
    let dispatched = Cell::new(false);
    let result = donor.serve_once(socket, |authenticated, request| {
        dispatched.set(true);
        runtime
            .dispatch(authenticated, request)
            .map_err(|_| rka_transport::TlsError::Admission)
    });
    match (result, dispatched.get()) {
        (Ok(()), _) => Ok(DonorIteration::Served),
        (Err(_), true) => Err(DirectSessionError::Ambiguous),
        (Err(_), false) => Ok(DonorIteration::Retry),
    }
}
