use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use crate::bridge::{
    BridgeMessage, BrokerOperation, CandidateBridgeOperation, Hash32, PublicBytes, RequestId,
    RoleExecutor, SidecarRole,
};
use crate::candidate::CandidateId;

use super::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
    RemoteKeyHandle, RemoteOperationHandle,
    broker_bridge_codec::{decode_finish, decode_public_key, decode_update, put_bytes},
    scheduler::{TeeCommand, TeeExecutor, TeeScheduler},
};

/// Android broker client backed by the authenticated donor Unix bridge.
#[derive(Clone, Debug)]
pub struct BridgeDonorBroker {
    scheduler: TeeScheduler,
    next_request: Arc<AtomicU64>,
    #[cfg(test)]
    successful_exchanges: Arc<AtomicUsize>,
    candidate: Option<CandidateId>,
}

#[derive(Debug)]
struct BridgeTeeExecutor {
    socket: PathBuf,
    executor: RoleExecutor,
    #[cfg(not(test))]
    successful_exchanges: Arc<AtomicUsize>,
}

impl BridgeDonorBroker {
    /// Creates one donor-only bridge client.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        let successful_exchanges = Arc::new(AtomicUsize::new(0));
        let scheduler = TeeScheduler::spawn(BridgeTeeExecutor {
            socket: socket.to_path_buf(),
            executor: RoleExecutor::new(SidecarRole::Donor),
            #[cfg(not(test))]
            successful_exchanges: Arc::clone(&successful_exchanges),
        })
        .unwrap_or_else(|_| TeeScheduler::closed());
        Self {
            scheduler,
            next_request: Arc::new(AtomicU64::new(1)),
            #[cfg(test)]
            successful_exchanges,
            candidate: None,
        }
    }

    #[cfg(test)]
    pub(super) fn new_authenticated_test(
        socket: &Path,
        exchanges: usize,
    ) -> Result<Self, crate::bridge::BridgeError> {
        let successful_exchanges = Arc::new(AtomicUsize::new(0));
        let executor = RoleExecutor::new_with_test_identity_counter(
            SidecarRole::Donor,
            exchanges,
            Arc::clone(&successful_exchanges),
        )?;
        let scheduler = TeeScheduler::spawn(BridgeTeeExecutor {
            socket: socket.to_path_buf(),
            executor,
        })
        .map_err(|_| crate::bridge::BridgeError::Io)?;
        Ok(Self {
            scheduler,
            next_request: Arc::new(AtomicU64::new(1)),
            successful_exchanges,
            candidate: None,
        })
    }

    #[cfg(test)]
    pub(super) fn authenticated_test_exchanges(&self) -> usize {
        self.successful_exchanges.load(Ordering::SeqCst)
    }

    fn exchange(
        &self,
        operation: CandidateBridgeOperation,
        payload: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let candidate = self.candidate.ok_or(BrokerFailure::Rejected)?;
        let internal_request_id = self.next_internal_request_id()?;
        self.scheduler
            .exchange(
                TeeCommand::new(candidate, internal_request_id, payload.to_vec())
                    .for_operation(operation),
            )
            .map_err(|_| BrokerFailure::Unavailable)
    }

    fn next_internal_request_id(&self) -> Result<u64, BrokerFailure> {
        self.next_request
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| BrokerFailure::Unavailable)
    }

    fn enqueue(
        &self,
        operation: CandidateBridgeOperation,
        payload: Vec<u8>,
    ) -> Result<(), BrokerFailure> {
        let candidate = self.candidate.ok_or(BrokerFailure::Rejected)?;
        let command = TeeCommand::new(candidate, self.next_internal_request_id()?, payload)
            .for_operation(operation);
        let pending = self
            .scheduler
            .submit(command)
            .map_err(|_| BrokerFailure::Unavailable)?;
        drop(pending);
        Ok(())
    }
}

impl TeeExecutor for BridgeTeeExecutor {
    fn exchange(&mut self, command: &TeeCommand) -> Result<Vec<u8>, BrokerFailure> {
        let request_id = RequestId::new(command.internal_request_id());
        let request = BridgeMessage::CandidateCommand(
            request_id,
            command.operation(),
            Hash32::new(*command.candidate().as_bytes()),
            PublicBytes::bounded(command.payload(), 0, 1_048_539)
                .map_err(|_| BrokerFailure::Rejected)?,
        );
        let response = self
            .executor
            .dispatch(BrokerOperation::Donor {
                socket_path: &self.socket,
                request: &request,
            })
            .map_err(|_| BrokerFailure::Unavailable)?;
        #[cfg(not(test))]
        self.successful_exchanges.fetch_add(1, Ordering::SeqCst);
        match response {
            BridgeMessage::CandidateReply(id, returned, bytes)
                if id == request_id && returned == command.operation() =>
            {
                Ok(bytes.as_slice().to_vec())
            }
            BridgeMessage::Error(..) => Err(BrokerFailure::Rejected),
            _ => Err(BrokerFailure::Unavailable),
        }
    }

    fn peer_died(&mut self) {
        let _ = self.executor.close();
    }
}

impl DonorBroker for BridgeDonorBroker {
    fn bind_candidate(&mut self, candidate: &CandidateId) {
        self.candidate = Some(*candidate);
    }

    fn generate(&mut self, request: BrokerGenerate<'_>) -> Result<GeneratedKey, BrokerFailure> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&request.alias);
        payload.extend_from_slice(&request.rkp_handle.as_array());
        put_bytes(&mut payload, request.challenge)?;
        put_bytes(&mut payload, request.candidate_aaid)?;
        put_bytes(&mut payload, &request.prior_transcript_hash)?;
        payload.push(u8::try_from(request.rkp_chain.len()).map_err(|_| BrokerFailure::Rejected)?);
        for certificate in request.rkp_chain {
            put_bytes(&mut payload, certificate)?;
        }
        let response = self.exchange(CandidateBridgeOperation::Generate, &payload)?;
        decode_public_key(&response)
    }

    fn begin(&mut self, request: BrokerBegin) -> Result<RemoteOperationHandle, BrokerFailure> {
        let response = self.exchange(
            CandidateBridgeOperation::Begin,
            &request.key_handle.as_array(),
        )?;
        Ok(RemoteOperationHandle::new(
            response.try_into().map_err(|_| BrokerFailure::Rejected)?,
        ))
    }

    fn update_aad(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<usize, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::UpdateAad, operation, input)?;
        decode_update(&response).map(|(consumed, _)| consumed)
    }

    fn update(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Update, operation, input)?;
        decode_update(&response).map(|(_, output)| output)
    }

    fn finish(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Finish, operation, input)?;
        decode_finish(&response)
    }

    fn abort(&mut self, operation: RemoteOperationHandle) -> Result<(), BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Abort, operation, &[])?;
        if response.is_empty() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }

    fn delete(&mut self, key: RemoteKeyHandle) -> Result<(), BrokerFailure> {
        let response = self.exchange(CandidateBridgeOperation::Delete, &key.as_array())?;
        if response.is_empty() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }

    fn get(&mut self, key: RemoteKeyHandle) -> Result<PublicKeyResult, BrokerFailure> {
        let response = self.exchange(CandidateBridgeOperation::Get, &key.as_array())?;
        decode_public_key(&response)
    }

    fn enqueue_abort(&mut self, operation: RemoteOperationHandle) -> Result<(), BrokerFailure> {
        let mut payload = Vec::with_capacity(20);
        payload.extend_from_slice(&operation.as_array());
        put_bytes(&mut payload, &[])?;
        self.enqueue(CandidateBridgeOperation::Abort, payload)
    }

    fn enqueue_delete(&mut self, key: RemoteKeyHandle) -> Result<(), BrokerFailure> {
        self.enqueue(CandidateBridgeOperation::Delete, key.as_array().to_vec())
    }

    fn broker_died(&mut self) {
        let _ = self.scheduler.peer_died();
    }
}

impl BridgeDonorBroker {
    fn operation(
        &self,
        kind: CandidateBridgeOperation,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let mut payload = Vec::with_capacity(20_usize.saturating_add(input.len()));
        payload.extend_from_slice(&operation.as_array());
        put_bytes(&mut payload, input)?;
        self.exchange(kind, &payload)
    }
}
