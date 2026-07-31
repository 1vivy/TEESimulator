use core::fmt;

use rka_protocol::{
    MessageKind, PeerSpkiHash, RequestId, SessionId, request_tombstone, session_tombstone, sha256,
};
use rka_state::{
    FailureBudget, FailureBudgetError, ReplayManager, StateError, StateStore, TombstoneTime,
};

use crate::{
    LiveSessionLease, SessionLifecycle,
    session_lifecycle::LifecycleError,
    session_types::{CsRng, PendingRequest, RequestContext, SessionError, SessionScope},
};

/// Bounded session and replay coordinator.
pub struct SessionManager<'a, S: StateStore, R: CsRng> {
    peer: PeerSpkiHash,
    epoch: u64,
    replay: ReplayManager<'a, S>,
    rng: R,
    lifecycle: SessionLifecycle,
    budget: FailureBudget<'a, S>,
}

impl<S: StateStore, R: CsRng> fmt::Debug for SessionManager<'_, S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionManager([redacted session state])")
    }
}

impl<'a, S: StateStore, R: CsRng> SessionManager<'a, S, R> {
    /// Loads persistent replay state for one paired peer and epoch.
    pub fn load(
        store: &'a S,
        rng: R,
        authority: (SessionScope, SessionLifecycle, u64),
    ) -> Result<Self, SessionError> {
        let (scope, lifecycle, now) = authority;
        if scope.epoch == 0 {
            return Err(SessionError::Profile);
        }
        Ok(Self {
            peer: scope.peer,
            epoch: scope.epoch,
            replay: ReplayManager::load(store)?,
            rng,
            lifecycle,
            budget: FailureBudget::load(store, peer_namespace(scope.peer), now)
                .map_err(map_budget)?,
        })
    }

    /// Opens one candidate-owned session and persists its replay tombstone.
    pub fn open_candidate(&mut self, now: u64) -> Result<LiveSessionLease, SessionError> {
        let _budget = self.budget.admit(now).map_err(map_budget)?;
        self.lifecycle.check_admission().map_err(map_lifecycle)?;
        for _ in 0..8 {
            let session_id = SessionId::new(self.random_array()?);
            if self.replay.session_id_retained(session_id.bytes())
                || self.lifecycle.contains(session_id)
            {
                continue;
            }
            let nonce = self.random_array()?;
            if nonce == session_id.bytes() {
                continue;
            }
            let lease = match self.lifecycle.acquire((session_id, nonce, now)) {
                Ok(lease) => lease,
                Err(LifecycleError::Duplicate) => continue,
                Err(error) => return Err(map_lifecycle(error)),
            };
            let key = session_tombstone(self.peer, self.epoch, session_id);
            match self.replay.persist_session(
                (&key, session_id.bytes()),
                TombstoneTime::new(now, self.epoch),
            ) {
                Ok(_) => return Ok(lease),
                Err(StateError::Replay) => {}
                Err(error) => return Err(SessionError::State(error)),
            }
        }
        Err(SessionError::RandomExhausted)
    }

    /// Persists correlation before releasing a non-idempotent dispatch permit.
    pub fn persist_request(
        &mut self,
        request: RequestContext,
    ) -> Result<PendingRequest, SessionError> {
        self.require_live(request.session, request.now)?;
        let request_id = self.unique_request_id()?;
        self.persist_pending(request, request_id)
    }

    /// Rejects reuse, including the same ID under another request kind.
    pub fn admit_request_id(
        &mut self,
        request: RequestContext,
        request_id: RequestId,
    ) -> Result<PendingRequest, SessionError> {
        self.require_live(request.session, request.now)?;
        if self.replay.request_id_retained(request_id.bytes()) {
            return Err(SessionError::Replay);
        }
        self.persist_pending(request, request_id)
    }

    fn persist_pending(
        &mut self,
        request: RequestContext,
        request_id: RequestId,
    ) -> Result<PendingRequest, SessionError> {
        let success_kind = expected_response(request.kind)?;
        let mut sequence = self
            .lifecycle
            .reserve_sequence(request.session)
            .map_err(map_lifecycle)?;
        let current = sequence.current();
        let key = request_tombstone(
            (self.peer, self.epoch, request.session),
            (request_id, request.kind),
        );
        let persisted = self.replay.persist_request(
            (&key, request_id.bytes()),
            TombstoneTime::new(request.now, self.epoch),
        )?;
        sequence.commit().map_err(map_lifecycle)?;
        drop(sequence);
        Ok(PendingRequest::new(
            (request_id, request.kind, success_kind, current),
            persisted,
        ))
    }

    /// Consumes one local admission-error budget unit.
    pub fn record_failure(&self, now: u64) -> Result<(), SessionError> {
        self.budget.record(now).map_err(map_budget)
    }

    fn require_live(&self, id: SessionId, now: u64) -> Result<(), SessionError> {
        self.lifecycle.touch(id, now).map_err(map_lifecycle)
    }

    fn unique_request_id(&self) -> Result<RequestId, SessionError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 16];
            self.rng.fill(&mut bytes)?;
            let id = RequestId::new(bytes);
            if !self.replay.request_id_retained(id.bytes()) {
                return Ok(id);
            }
        }
        Err(SessionError::RandomExhausted)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N], SessionError> {
        let mut bytes = [0_u8; N];
        self.rng.fill(&mut bytes)?;
        Ok(bytes)
    }
}

const fn expected_response(request: MessageKind) -> Result<MessageKind, SessionError> {
    match request {
        MessageKind::Hello => Ok(MessageKind::HelloAck),
        MessageKind::Generate
        | MessageKind::Get
        | MessageKind::List
        | MessageKind::Delete
        | MessageKind::Begin
        | MessageKind::UpdateAad
        | MessageKind::Update
        | MessageKind::Finish
        | MessageKind::Abort => Ok(MessageKind::Result),
        MessageKind::HelloAck | MessageKind::Result | MessageKind::Error | _ => {
            Err(SessionError::Correlation)
        }
    }
}

const fn map_lifecycle(error: LifecycleError) -> SessionError {
    match error {
        LifecycleError::Draining => SessionError::Draining,
        LifecycleError::Capacity => SessionError::Capacity,
        LifecycleError::Duplicate => SessionError::RandomExhausted,
        LifecycleError::Missing => SessionError::Missing,
        LifecycleError::Expired => SessionError::Expired,
        LifecycleError::TimeRegression => SessionError::TimeRegression,
    }
}

const fn map_budget(error: FailureBudgetError) -> SessionError {
    match error {
        FailureBudgetError::RateLimited => SessionError::RateLimited,
        FailureBudgetError::State(error) => SessionError::State(error),
        _ => SessionError::State(StateError::Corrupt),
    }
}

fn peer_namespace(peer: PeerSpkiHash) -> [u8; 32] {
    sha256(&session_tombstone(peer, 0, SessionId::new([0; 32])))
}
