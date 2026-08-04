use std::{
    collections::VecDeque,
    sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
    thread,
};

use crate::{bridge::CandidateBridgeOperation, candidate::CandidateId};

use super::{BrokerFailure, DonorError, quota::MAX_BROKER_QUEUE_DONOR_WIDE};

/// Owned physical-TEE command with donor-internal correlation.
#[derive(Clone, Debug)]
pub struct TeeCommand {
    candidate: CandidateId,
    internal_request_id: u64,
    operation: CandidateBridgeOperation,
    payload: Vec<u8>,
}

impl TeeCommand {
    /// Creates a scheduler command for deterministic executor tests.
    #[must_use]
    pub const fn new(candidate: CandidateId, internal_request_id: u64, payload: Vec<u8>) -> Self {
        Self {
            candidate,
            internal_request_id,
            operation: CandidateBridgeOperation::Generate,
            payload,
        }
    }

    pub(super) const fn for_operation(mut self, operation: CandidateBridgeOperation) -> Self {
        self.operation = operation;
        self
    }

    /// Returns the authenticated candidate coordinate.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateId {
        &self.candidate
    }

    /// Returns the candidate-scoped internal request id.
    #[must_use]
    pub const fn internal_request_id(&self) -> u64 {
        self.internal_request_id
    }

    /// Returns the bounded public command payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(super) const fn operation(&self) -> CandidateBridgeOperation {
        self.operation
    }
}

/// Physical TEE exchange boundary owned by the scheduler thread.
pub trait TeeExecutor: Send + 'static {
    /// Executes one command while no other physical TEE command is active.
    fn exchange(&mut self, command: &TeeCommand) -> Result<Vec<u8>, BrokerFailure>;

    /// Cancels active transport state after broker death.
    fn peer_died(&mut self) {}
}

struct ScheduledRequest {
    command: TeeCommand,
    response: SyncSender<Result<TeeReply, DonorError>>,
}

struct CandidateQueue {
    candidate: CandidateId,
    requests: VecDeque<ScheduledRequest>,
}

/// Donor-wide FIFO-per-candidate round-robin scheduler handle.
#[derive(Clone, Debug)]
pub struct TeeScheduler {
    requests: SyncSender<ScheduledRequest>,
    controls: Sender<ControlEvent>,
}

#[derive(Clone, Copy, Debug)]
enum ControlEvent {
    PeerDied,
}

impl TeeScheduler {
    /// Starts the single physical TEE worker.
    pub fn spawn(mut executor: impl TeeExecutor) -> Result<Self, DonorError> {
        let (requests, receiver) = mpsc::sync_channel(MAX_BROKER_QUEUE_DONOR_WIDE);
        let (controls, control_receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("rka-tee-scheduler".to_owned())
            .spawn(move || run(&receiver, &control_receiver, &mut executor))
            .map_err(|_| DonorError::Broker)?;
        drop(worker);
        Ok(Self { requests, controls })
    }

    pub(super) fn closed() -> Self {
        let (requests, receiver) = mpsc::sync_channel(0);
        let (controls, control_receiver) = mpsc::channel();
        drop(receiver);
        drop(control_receiver);
        Self { requests, controls }
    }

    /// Queues one command without waiting for its physical exchange.
    pub fn submit(&self, command: TeeCommand) -> Result<PendingTeeReply, DonorError> {
        let (response, receiver) = mpsc::sync_channel(1);
        let request = ScheduledRequest { command, response };
        self.requests
            .try_send(request)
            .map_err(|error| match error {
                TrySendError::Full(_) => DonorError::Capacity,
                TrySendError::Disconnected(_) => DonorError::Broker,
            })?;
        Ok(PendingTeeReply { receiver })
    }

    /// Enqueues broker death without synchronously calling the worker.
    pub fn peer_died(&self) -> Result<(), DonorError> {
        self.controls
            .send(ControlEvent::PeerDied)
            .map_err(|_| DonorError::Broker)
    }

    pub(super) fn exchange(&self, command: TeeCommand) -> Result<Vec<u8>, DonorError> {
        self.submit(command)?.wait().map(TeeReply::into_payload)
    }
}

/// Pending correlated scheduler response.
#[derive(Debug)]
pub struct PendingTeeReply {
    receiver: Receiver<Result<TeeReply, DonorError>>,
}

impl PendingTeeReply {
    /// Waits for the single physical worker to finish this command.
    pub fn wait(self) -> Result<TeeReply, DonorError> {
        self.receiver.recv().map_err(|_| DonorError::Broker)?
    }
}

/// Correlated physical TEE response.
#[derive(Debug, Eq, PartialEq)]
pub struct TeeReply {
    candidate: CandidateId,
    internal_request_id: u64,
    payload: Vec<u8>,
}

impl TeeReply {
    /// Returns the authenticated candidate coordinate.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateId {
        &self.candidate
    }

    /// Returns the candidate-scoped internal request id.
    #[must_use]
    pub const fn internal_request_id(&self) -> u64 {
        self.internal_request_id
    }

    fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

fn run(
    receiver: &Receiver<ScheduledRequest>,
    controls: &Receiver<ControlEvent>,
    executor: &mut impl TeeExecutor,
) {
    let mut queues = VecDeque::new();
    while let Ok(request) = receiver.recv() {
        enqueue(&mut queues, request);
        loop {
            while let Ok(pending) = receiver.try_recv() {
                enqueue(&mut queues, pending);
            }
            let Some(mut candidate_queue) = queues.pop_front() else {
                break;
            };
            let Some(request) = candidate_queue.requests.pop_front() else {
                continue;
            };
            if !candidate_queue.requests.is_empty() {
                queues.push_back(candidate_queue);
            }
            let result = executor
                .exchange(&request.command)
                .map(|payload| TeeReply {
                    candidate: request.command.candidate,
                    internal_request_id: request.command.internal_request_id,
                    payload,
                })
                .map_err(|_| DonorError::Broker);
            let _ = request.response.send(result);
            while matches!(controls.try_recv(), Ok(ControlEvent::PeerDied)) {
                executor.peer_died();
                fail_queued(&mut queues);
            }
        }
    }
}

fn fail_queued(queues: &mut VecDeque<CandidateQueue>) {
    for queue in queues.drain(..) {
        for request in queue.requests {
            let _ = request.response.send(Err(DonorError::Broker));
        }
    }
}

fn enqueue(queues: &mut VecDeque<CandidateQueue>, request: ScheduledRequest) {
    if let Some(queue) = queues
        .iter_mut()
        .find(|queue| queue.candidate == request.command.candidate)
    {
        queue.requests.push_back(request);
        return;
    }
    queues.push_back(CandidateQueue {
        candidate: request.command.candidate,
        requests: VecDeque::from([request]),
    });
}
