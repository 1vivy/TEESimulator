#![allow(
    clippy::redundant_pub_crate,
    reason = "the crate-private actor is shared with the sibling direct-session module"
)]

use std::{
    sync::mpsc::{self, SyncSender},
    thread,
};

use crate::candidate::CandidateId;

use super::DonorError;

struct ActorRequest<I> {
    input: I,
    response: SyncSender<Result<Vec<u8>, DonorError>>,
}

#[derive(Clone, Debug)]
pub(crate) struct CandidateActor<I> {
    candidate: CandidateId,
    requests: SyncSender<ActorRequest<I>>,
}

impl<I: Send + 'static> CandidateActor<I> {
    pub(crate) fn spawn(
        candidate: CandidateId,
        mut handler: impl FnMut(I) -> Result<Vec<u8>, DonorError> + Send + 'static,
    ) -> Result<Self, DonorError> {
        let (requests, receiver) = mpsc::sync_channel::<ActorRequest<I>>(1);
        let worker = thread::Builder::new()
            .name("rka-candidate-actor".to_owned())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let response = handler(request.input);
                    if request.response.send(response).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| DonorError::Broker)?;
        drop(worker);
        Ok(Self {
            candidate,
            requests,
        })
    }

    pub(crate) fn dispatch(
        &self,
        candidate: &CandidateId,
        input: I,
    ) -> Result<Vec<u8>, DonorError> {
        if candidate != &self.candidate {
            return Err(DonorError::Unpaired);
        }
        let (response, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(ActorRequest { input, response })
            .map_err(|_| DonorError::Broker)?;
        receiver.recv().map_err(|_| DonorError::Broker)?
    }
}
