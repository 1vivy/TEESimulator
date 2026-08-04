use std::{
    cell::Cell,
    collections::HashMap,
    net::SocketAddrV4,
    path::{Path, PathBuf},
    sync::mpsc::{self, SyncSender},
    time::Duration,
};

use crate::{
    bridge::{BridgeMessage, ExchangeRole, decode_frame, encode_frame},
    candidate::{CandidateId, CandidateLayout},
    direct_bridge::DirectBridgeAdapter,
    direct_profile::{DialMode, DirectProfile},
    donor::actor::CandidateActor,
};

use super::super::{
    BUDGET, DirectSessionError, PORT, authenticated_profile, candidate_diagnostic,
    candidate_local_socket_path, connect_bound, donor_client, tls_status,
};

#[doc(hidden)]
pub fn run_donor_bridge() -> Result<(), DirectSessionError> {
    let (state, profiles) =
        crate::direct_profile::load_donor_profiles().map_err(|_| DirectSessionError::State)?;
    let bridge = bridge_actor(state.clone())?;
    let (failures, receiver) = mpsc::sync_channel(1);
    for (profile, _) in profiles {
        if profile.dial_mode != DialMode::DonorDials {
            return Err(DirectSessionError::State);
        }
        let authenticated = authenticated_profile(&state, &profile)?;
        let candidate = *authenticated.candidate();
        let bridge = bridge.clone();
        let actor = CandidateActor::spawn(candidate, move |request| {
            let (response, result) = mpsc::sync_channel(1);
            bridge
                .send(BridgeRequest {
                    candidate,
                    request,
                    response,
                })
                .map_err(|_| crate::donor::DonorError::Broker)?;
            result
                .recv()
                .map_err(|_| crate::donor::DonorError::Broker)?
        })
        .map_err(|_| DirectSessionError::State)?;
        let state = state.clone();
        let failures = failures.clone();
        std::thread::Builder::new()
            .name("rka-bridge-profile-supervisor".to_owned())
            .spawn(move || {
                let result = run_bridge_profile((&actor, &state, &profile), &candidate);
                let _ = failures.send(result);
            })
            .map_err(|_| DirectSessionError::State)?;
    }
    drop(failures);
    receiver.recv().map_err(|_| DirectSessionError::State)?
}

struct BridgeRequest {
    candidate: CandidateId,
    request: Vec<u8>,
    response: SyncSender<Result<Vec<u8>, crate::donor::DonorError>>,
}

fn bridge_actor(state: PathBuf) -> Result<SyncSender<BridgeRequest>, DirectSessionError> {
    let (sender, receiver) = mpsc::sync_channel::<BridgeRequest>(32);
    std::thread::Builder::new()
        .name("rka-donor-bridge".to_owned())
        .spawn(move || {
            let mut adapters = HashMap::<CandidateId, DirectBridgeAdapter>::new();
            while let Ok(request) = receiver.recv() {
                let adapter = adapters.entry(request.candidate).or_insert_with(|| {
                    DirectBridgeAdapter::new(
                        CandidateLayout::new(&state, &request.candidate).root(),
                        candidate_local_socket_path(&state, &request.candidate),
                    )
                });
                let result = dispatch_bridge(adapter, &request.candidate, &request.request)
                    .map_err(|()| crate::donor::DonorError::Broker);
                if request.response.send(result).is_err() {
                    break;
                }
            }
        })
        .map_err(|_| DirectSessionError::State)?;
    Ok(sender)
}

fn dispatch_bridge(
    adapter: &mut DirectBridgeAdapter,
    candidate: &CandidateId,
    request: &[u8],
) -> Result<Vec<u8>, ()> {
    let request = decode_frame(request, ExchangeRole::CandidateRequest).map_err(|_| ())?;
    if matches!(
        &request,
        BridgeMessage::CandidateCommand(_, _, encoded, _)
            if encoded.as_array() != candidate.as_bytes()
    ) {
        return Err(());
    }
    let prepared = adapter.prepare(request)?;
    let response = adapter.dispatch(&prepared).map_err(|_| ())?;
    let response = DirectBridgeAdapter::finish(&prepared, response)?;
    encode_frame(&response, ExchangeRole::CandidateResponse)
        .map(|encoded| encoded.as_slice().to_vec())
        .map_err(|_| ())
}

fn run_bridge_profile(
    context: (&CandidateActor<Vec<u8>>, &Path, &DirectProfile),
    candidate: &CandidateId,
) -> Result<(), DirectSessionError> {
    let (actor, state, profile) = context;
    loop {
        let donor = donor_client(state, profile)?;
        let Ok(socket) = connect_bound(
            profile.listen_interface,
            SocketAddrV4::new(profile.endpoint, PORT),
            BUDGET,
        ) else {
            candidate_diagnostic(state, candidate, "donor_pre_dispatch_io");
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let dispatched = Cell::new(false);
        let result = donor.serve_once(socket, |authenticated, request| {
            dispatched.set(true);
            actor
                .dispatch(authenticated.candidate(), request.to_vec())
                .map_err(|_| rka_transport::TlsError::Admission)
        });
        match (result, dispatched.get()) {
            (Ok(()), _) => {}
            (Err(error), true) => {
                candidate_diagnostic(state, candidate, &tls_status(error, "donor_ambiguous"));
                return Err(DirectSessionError::Ambiguous);
            }
            (Err(error), false) => {
                candidate_diagnostic(state, candidate, &tls_status(error, "donor_pre_dispatch"));
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
