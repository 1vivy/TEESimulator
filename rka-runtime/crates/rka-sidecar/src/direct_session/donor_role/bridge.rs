use std::{
    cell::Cell,
    collections::HashMap,
    net::SocketAddrV4,
    path::Path,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};

use crate::{
    bridge::{BridgeMessage, ExchangeRole, decode_frame, encode_frame},
    candidate::CandidateId,
    direct_bridge::DirectBridgeAdapter,
    direct_profile::DialMode,
    donor::actor::CandidateActor,
};

use super::super::{
    BUDGET, DirectSessionError, DonorProfileBinding, PORT, connect_bound, diagnostic, donor_client,
    local_socket_path, resolve_donor_bindings, tls_status,
};

#[doc(hidden)]
pub fn run_donor_bridge() -> Result<(), DirectSessionError> {
    let (state, source, profiles) =
        crate::direct_profile::load_donor_profiles().map_err(|_| DirectSessionError::State)?;
    let bindings = resolve_donor_bindings(
        &state,
        source,
        profiles.into_iter().map(|(profile, _)| profile).collect(),
    )?;
    let adapters = bindings
        .iter()
        .map(|binding| {
            (
                *binding.authenticated.candidate(),
                DirectBridgeAdapter::new(
                    &binding.runtime_root,
                    local_socket_path(&binding.runtime_root),
                ),
            )
        })
        .collect();
    let bridge = bridge_actor(adapters)?;
    let (failures, receiver) = mpsc::sync_channel(1);
    for binding in bindings {
        if binding.profile.dial_mode != DialMode::DonorDials {
            return Err(DirectSessionError::State);
        }
        let candidate = *binding.authenticated.candidate();
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
                let result = run_bridge_profile((&actor, &state, &binding));
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

fn bridge_actor(
    mut adapters: HashMap<CandidateId, DirectBridgeAdapter>,
) -> Result<SyncSender<BridgeRequest>, DirectSessionError> {
    let (sender, receiver) = mpsc::sync_channel::<BridgeRequest>(32);
    std::thread::Builder::new()
        .name("rka-donor-bridge".to_owned())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                let result = adapters
                    .get_mut(&request.candidate)
                    .ok_or(crate::donor::DonorError::Broker)
                    .and_then(|adapter| {
                        dispatch_bridge(adapter, &request.candidate, &request.request)
                            .map_err(|()| crate::donor::DonorError::Broker)
                    });
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
    context: (&CandidateActor<Vec<u8>>, &Path, &DonorProfileBinding),
) -> Result<(), DirectSessionError> {
    let (actor, state, binding) = context;
    loop {
        let donor = donor_client(state, binding)?;
        let Ok(socket) = connect_bound(
            binding.profile.listen_interface,
            SocketAddrV4::new(binding.profile.endpoint, PORT),
            BUDGET,
        ) else {
            diagnostic(&binding.runtime_root, "donor_pre_dispatch_io");
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
                diagnostic(&binding.runtime_root, &tls_status(error, "donor_ambiguous"));
                return Err(DirectSessionError::Ambiguous);
            }
            (Err(error), false) => {
                diagnostic(
                    &binding.runtime_root,
                    &tls_status(error, "donor_pre_dispatch"),
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
