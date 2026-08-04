#![allow(
    clippy::redundant_pub_crate,
    reason = "the private support module exports its fixture only to the parent integration test"
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, Sender},
};

use rka_sidecar::{
    candidate::CandidateId,
    donor::{BrokerFailure, TeeCommand, TeeExecutor, donor_lock_depth},
};

pub(super) struct CountingTee {
    pub order: Arc<Mutex<Vec<(CandidateId, u64)>>>,
    pub active: Arc<AtomicUsize>,
    pub maximum: Arc<AtomicUsize>,
    pub first_started: Sender<()>,
    pub first_release: Receiver<()>,
    pub entry_depths: Arc<Mutex<Vec<usize>>>,
}

impl TeeExecutor for CountingTee {
    fn exchange(&mut self, command: &TeeCommand) -> Result<Vec<u8>, BrokerFailure> {
        let depth = donor_lock_depth();
        assert_eq!(depth, 0, "donor lock held across physical TEE exchange");
        self.entry_depths
            .lock()
            .map_err(|_| BrokerFailure::Unavailable)?
            .push(depth);
        let active = self.active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.maximum.fetch_max(active, Ordering::SeqCst);
        self.order
            .lock()
            .map_err(|_| BrokerFailure::Unavailable)?
            .push((*command.candidate(), command.internal_request_id()));
        if command.internal_request_id() == 1 && command.payload() == b"a1" {
            self.first_started
                .send(())
                .map_err(|_| BrokerFailure::Unavailable)?;
            self.first_release
                .recv()
                .map_err(|_| BrokerFailure::Unavailable)?;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(command.payload().to_vec())
    }
}
