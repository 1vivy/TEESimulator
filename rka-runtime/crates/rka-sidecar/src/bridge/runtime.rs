use std::{os::unix::net::UnixListener, path::Path, sync::Arc, time::Duration};

#[cfg(test)]
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

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
    #[cfg(test)]
    identity_sources: Mutex<VecDeque<super::identity_source::TestIdentitySource>>,
    #[cfg(test)]
    successful_test_authentications: AtomicUsize,
}

impl RoleExecutor {
    /// Creates one role-isolated executor.
    pub fn new(role: SidecarRole) -> Self {
        Self {
            role,
            shared: Shared::new(),
            #[cfg(test)]
            identity_sources: Mutex::new(VecDeque::new()),
            #[cfg(test)]
            successful_test_authentications: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_identities(
        role: SidecarRole,
        count: usize,
    ) -> Result<Self, BridgeError> {
        let broker_role = match role {
            SidecarRole::Donor => BrokerRole::Donor,
            SidecarRole::Candidate => BrokerRole::Candidate,
        };
        let mut sources = VecDeque::new();
        sources
            .try_reserve(count)
            .map_err(|_| BridgeError::Allocation)?;
        for _ in 0..count {
            sources.push_back(super::test_identity::ready_source(broker_role)?);
        }
        Ok(Self {
            role,
            shared: Shared::new(),
            identity_sources: Mutex::new(sources),
            successful_test_authentications: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn successful_test_authentications(&self) -> usize {
        self.successful_test_authentications.load(Ordering::Acquire)
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
                #[cfg(test)]
                let (authenticated, _identity_source) =
                    self.authenticate(super::identity::AuthenticationRequest {
                        stream: &stream,
                        role: BrokerRole::Donor,
                        deadline: &deadline,
                    })?;
                #[cfg(not(test))]
                let authenticated =
                    authenticate_broker_peer(&stream, BrokerRole::Donor, &deadline)?;
                let correlation = Correlation::new(request, permit.generation)?;
                let frame = encode_frame(request, ExchangeRole::DonorRequest)?;
                write_message(&stream, &frame, &deadline)?;
                let response = read_message(&stream, ExchangeRole::DonorResponse, &deadline)?;
                permit.stage()?;
                authenticated.revalidate(&stream, &deadline)?;
                if !correlation.accepts(&response, permit.generation) {
                    return Err(BridgeError::Correlation);
                }
                Ok(permit.expose(response))
            }
            (SidecarRole::Candidate, BrokerOperation::Candidate { listener, response }) => {
                let stream = accept_peer(listener, &deadline)?;
                permit.attach(&stream)?;
                deadline.remaining()?;
                #[cfg(test)]
                let (authenticated, _identity_source) =
                    self.authenticate(super::identity::AuthenticationRequest {
                        stream: &stream,
                        role: BrokerRole::Candidate,
                        deadline: &deadline,
                    })?;
                #[cfg(not(test))]
                let authenticated =
                    authenticate_broker_peer(&stream, BrokerRole::Candidate, &deadline)?;
                let request = read_message(&stream, ExchangeRole::CandidateRequest, &deadline)?;
                permit.stage()?;
                if request.request_id() != response.request_id() {
                    return Err(BridgeError::Correlation);
                }
                let frame = encode_frame(response, ExchangeRole::CandidateResponse)?;
                write_message(&stream, &frame, &deadline)?;
                authenticated.revalidate(&stream, &deadline)?;
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

    #[cfg(test)]
    fn authenticate(
        &self,
        request: super::identity::AuthenticationRequest<'_>,
    ) -> Result<
        (
            super::peer_authorization::PeerAuthorization,
            Option<super::identity_source::TestIdentitySource>,
        ),
        BridgeError,
    > {
        use super::identity::authenticate_with_source;

        let source = self
            .identity_sources
            .lock()
            .map_err(|_| BridgeError::Io)?
            .pop_front();
        if let Some(mut source) = source {
            let authorization = authenticate_with_source(&mut source, request)?;
            self.successful_test_authentications
                .fetch_add(1, Ordering::AcqRel);
            Ok((authorization, Some(source)))
        } else {
            authenticate_broker_peer(request.stream, request.role, request.deadline)
                .map(|authorization| (authorization, None))
        }
    }
}
