use std::{os::unix::net::UnixListener, path::Path, sync::Arc, time::Duration};

use super::{
    BridgeError, BridgeMessage, BrokerRole, Correlation, ExchangeRole,
    deadline::{Control, Deadline},
    encode_frame,
    executor_state::{RuntimeSnapshot, Shared},
    identity::authenticate_broker_peer,
    socket::{accept_peer, connect_path, read_message, write_message},
};

const DEFAULT_BUDGET: Duration = Duration::from_secs(5);

/// Sidecar topology role with an independent executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SidecarRole {
    /// Sidecar connects to the donor broker server.
    Donor,
    /// Sidecar accepts the candidate broker client.
    Candidate,
}

/// Closed bridge work accepted by the role executor.
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerOperation<'a> {
    /// Connect, authenticate, send a request, and receive its response.
    Donor {
        /// Root broker socket path.
        socket_path: &'a Path,
        /// Typed public-only request.
        request: &'a BridgeMessage,
    },
    /// Accept, authenticate, receive a request, and send its response.
    Candidate {
        /// Root-owned listening socket.
        listener: &'a UnixListener,
        /// Typed public-only response.
        response: &'a BridgeMessage,
    },
}

/// Bounded per-role executor for closed typed bridge operations.
#[derive(Debug)]
pub struct RoleExecutor {
    role: SidecarRole,
    shared: Arc<Shared>,
}

impl RoleExecutor {
    /// Creates one role-isolated executor.
    pub fn new(role: SidecarRole) -> Self {
        Self {
            role,
            shared: Shared::new(),
        }
    }

    /// Returns the fixed topology role.
    pub const fn role(&self) -> SidecarRole {
        self.role
    }

    /// Dispatches closed bridge work within five seconds.
    pub fn dispatch(&self, operation: BrokerOperation<'_>) -> Result<BridgeMessage, BridgeError> {
        self.dispatch_with_budget(operation, DEFAULT_BUDGET)
    }

    /// Dispatches closed bridge work within a smaller aggregate budget.
    pub fn dispatch_with_budget(
        &self,
        operation: BrokerOperation<'_>,
        budget: Duration,
    ) -> Result<BridgeMessage, BridgeError> {
        let control = Control::new()?;
        let deadline = Deadline::new(budget, Arc::clone(&control))?;
        let mut permit = self.shared.acquire(&deadline, control)?;
        match (self.role, operation) {
            (
                SidecarRole::Donor,
                BrokerOperation::Donor {
                    socket_path,
                    request,
                },
            ) => {
                let stream = connect_path(socket_path, &deadline)?;
                permit.attach(&stream)?;
                deadline.remaining()?;
                let authenticated = authenticate_broker_peer(&stream, BrokerRole::Donor)?;
                deadline.remaining()?;
                let correlation = Correlation::new(request, permit.generation)?;
                let frame = encode_frame(request, ExchangeRole::DonorRequest)?;
                write_message(&stream, &frame, &deadline)?;
                let response = read_message(&stream, ExchangeRole::DonorResponse, &deadline)?;
                permit.stage()?;
                authenticated.revalidate(&stream)?;
                deadline.remaining()?;
                if !correlation.accepts(&response, permit.generation) {
                    return Err(BridgeError::Correlation);
                }
                Ok(permit.expose(response))
            }
            (SidecarRole::Candidate, BrokerOperation::Candidate { listener, response }) => {
                let stream = accept_peer(listener, &deadline)?;
                permit.attach(&stream)?;
                deadline.remaining()?;
                let authenticated = authenticate_broker_peer(&stream, BrokerRole::Candidate)?;
                deadline.remaining()?;
                let request = read_message(&stream, ExchangeRole::CandidateRequest, &deadline)?;
                permit.stage()?;
                if request.request_id() != response.request_id() {
                    return Err(BridgeError::Correlation);
                }
                let frame = encode_frame(response, ExchangeRole::CandidateResponse)?;
                write_message(&stream, &frame, &deadline)?;
                authenticated.revalidate(&stream)?;
                deadline.remaining()?;
                Ok(permit.expose(request))
            }
            _ => Err(BridgeError::WrongRole),
        }
    }

    /// Advances generation only after every prior operation is gone.
    pub fn reconnect(&self) -> Result<u64, BridgeError> {
        self.shared.reconnect()
    }

    /// Cancels active sockets and wakes every queued operation.
    pub fn close(&self) -> Result<(), BridgeError> {
        self.shared.close()
    }

    /// Captures cleanup counters without handler material.
    pub fn snapshot(&self) -> Result<RuntimeSnapshot, BridgeError> {
        self.shared.snapshot()
    }
}
