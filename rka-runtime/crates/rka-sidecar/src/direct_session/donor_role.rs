use std::{cell::Cell, net::SocketAddrV4, path::Path, time::Duration};

use crate::{
    LifecycleRole,
    bridge::{
        BridgeError, ExchangeRole, decode_frame as decode_bridge_frame,
        encode_frame as encode_bridge_frame,
    },
    direct_bridge::DirectBridgeAdapter,
    direct_profile::{DialMode, DirectProfile},
    donor::DonorRuntime,
};

use super::{
    BUDGET, DirectSessionError, PORT, connect_bound, diagnostic, donor_client, tls_status,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DonorIteration {
    Served,
    Retry,
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
pub fn run_donor_bridge() -> Result<(), DirectSessionError> {
    let (state, profile, _) =
        crate::direct_profile::load(LifecycleRole::Donor).map_err(|_| DirectSessionError::State)?;
    if profile.dial_mode != DialMode::DonorDials {
        return Err(DirectSessionError::State);
    }
    let mut adapter = DirectBridgeAdapter::new(&state);
    loop {
        let donor = donor_client(&state, &profile)?;
        let Ok(socket) = connect_bound(
            profile.listen_interface,
            SocketAddrV4::new(profile.endpoint, PORT),
            BUDGET,
        ) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let dispatched = Cell::new(false);
        let result = donor.serve_once(socket, |_authenticated, request| {
            let request = decode_bridge_frame(request, ExchangeRole::CandidateRequest)
                .map_err(|_| rka_transport::TlsError::Admission)?;
            let prepared = adapter.prepare(request).map_err(|()| {
                diagnostic(&state, "donor_bridge_prepare");
                rka_transport::TlsError::Admission
            })?;
            dispatched.set(true);
            let response = adapter.dispatch(&prepared).map_err(|error| {
                diagnostic(&state, &format!("donor_bridge_{}", bridge_status(error)));
                rka_transport::TlsError::Admission
            })?;
            let response = DirectBridgeAdapter::finish(&prepared, response).map_err(|()| {
                diagnostic(&state, "donor_bridge_finish");
                rka_transport::TlsError::Admission
            })?;
            let encoded =
                encode_bridge_frame(&response, ExchangeRole::CandidateResponse).map_err(|_| {
                    diagnostic(&state, "donor_bridge_encode");
                    rka_transport::TlsError::Admission
                })?;
            Ok(encoded.as_slice().to_vec())
        });
        match (result, dispatched.get()) {
            (Ok(()), _) => {}
            (Err(error), true) => {
                diagnostic(&state, &tls_status(error, "donor_ambiguous"));
                return Err(DirectSessionError::Ambiguous);
            }
            (Err(error), false) => {
                diagnostic(&state, &tls_status(error, "donor_pre_dispatch"));
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

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

const fn bridge_status(error: BridgeError) -> &'static str {
    match error {
        BridgeError::Deadline => "deadline",
        BridgeError::PeerDied => "peer_died",
        BridgeError::PeerIdentity => "peer_identity",
        BridgeError::TrustedState => "trusted_state",
        BridgeError::Io => "io",
        BridgeError::Correlation => "correlation",
        BridgeError::Generation => "generation",
        BridgeError::Capacity => "capacity",
        BridgeError::QueueSaturated => "queue_saturated",
        BridgeError::Cancelled => "cancelled",
        _ => "protocol",
    }
}
