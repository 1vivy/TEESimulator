use ring::rand::{SecureRandom, SystemRandom};
use rka_protocol::{
    MessageKind, PeerSpkiHash, RequestId, SessionId, request_tombstone, session_tombstone,
};
use rka_state::{PersistedTombstone, ReplayManager, StateError, StateStore, TombstoneTime};
use thiserror::Error;

const MAX_SESSIONS: usize = 4;
const IDLE_SECONDS: u64 = 30;
const TTL_SECONDS: u64 = 120;
const MAX_ADMISSION_FAILURES: u8 = 8;

/// Fixed paired-peer coordinates for a session manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SessionScope {
    peer: PeerSpkiHash,
    epoch: u64,
}

impl SessionScope {
    /// Creates nonzero-epoch peer coordinates.
    #[must_use]
    pub const fn new(peer: PeerSpkiHash, epoch: u64) -> Self {
        Self { peer, epoch }
    }
}

/// Correlation and time for one candidate-generated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestContext {
    session: SessionId,
    kind: MessageKind,
    now: u64,
}

impl RequestContext {
    /// Creates request coordinates under one live session.
    #[must_use]
    pub const fn new(session: SessionId, kind: MessageKind, now: u64) -> Self {
        Self { session, kind, now }
    }
}

/// Injectable cryptographically secure random source.
pub trait CsRng {
    /// Fills the complete output or fails closed.
    fn fill(&self, output: &mut [u8]) -> Result<(), SessionError>;
}

/// Production randomness backed by ring `SystemRandom`.
#[derive(Debug)]
pub struct SystemCsRng(SystemRandom);

impl Default for SystemCsRng {
    fn default() -> Self {
        Self(SystemRandom::new())
    }
}

impl CsRng for SystemCsRng {
    fn fill(&self, output: &mut [u8]) -> Result<(), SessionError> {
        self.0.fill(output).map_err(|_| SessionError::Random)
    }
}

/// Authenticated session with candidate-owned identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveSession {
    id: SessionId,
    candidate_nonce: [u8; 32],
    created: u64,
    last_activity: u64,
}

impl LiveSession {
    /// Returns the candidate-owned session identifier.
    #[must_use]
    pub const fn id(self) -> SessionId {
        self.id
    }

    /// Returns the candidate nonce, which is distinct from the session ID.
    #[must_use]
    pub const fn candidate_nonce(self) -> [u8; 32] {
        self.candidate_nonce
    }
}

/// Opaque proof that dispatch may occur after persistence.
#[derive(Debug)]
pub struct RequestPermit {
    request_id: RequestId,
    kind: MessageKind,
    persisted: PersistedTombstone,
}

impl RequestPermit {
    /// Returns correlation values that every response must copy.
    #[must_use]
    pub const fn correlation(&self) -> (RequestId, MessageKind) {
        (self.request_id, self.kind)
    }

    /// Returns the persisted canonical request tuple.
    #[must_use]
    pub fn replay_key(&self) -> &[u8] {
        self.persisted.key()
    }
}

/// Bounded session and replay coordinator.
#[derive(Debug)]
pub struct SessionManager<'a, S: StateStore, R: CsRng> {
    peer: PeerSpkiHash,
    epoch: u64,
    replay: ReplayManager<'a, S>,
    rng: R,
    sessions: Vec<LiveSession>,
    requests: Vec<(RequestId, MessageKind)>,
    failures: u8,
}

impl<'a, S: StateStore, R: CsRng> SessionManager<'a, S, R> {
    /// Loads persistent replay state for one paired peer and epoch.
    pub fn load(store: &'a S, rng: R, scope: SessionScope) -> Result<Self, SessionError> {
        if scope.epoch == 0 {
            return Err(SessionError::Profile);
        }
        Ok(Self {
            peer: scope.peer,
            epoch: scope.epoch,
            replay: ReplayManager::load(store)?,
            rng,
            sessions: Vec::with_capacity(MAX_SESSIONS),
            requests: Vec::with_capacity(64),
            failures: 0,
        })
    }

    /// Opens one candidate-owned session and persists its replay tombstone.
    pub fn open_candidate(&mut self, now: u64) -> Result<LiveSession, SessionError> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::Capacity);
        }
        let session_id = self.unique_session_id()?;
        let mut nonce = [0_u8; 32];
        self.rng.fill(&mut nonce)?;
        if nonce == session_id.bytes() {
            return Err(SessionError::Collision);
        }
        let key = session_tombstone(self.peer, self.epoch, session_id);
        self.replay
            .persist(&key, TombstoneTime::new(now, self.epoch))?;
        let session = LiveSession {
            id: session_id,
            candidate_nonce: nonce,
            created: now,
            last_activity: now,
        };
        self.sessions.push(session);
        Ok(session)
    }

    /// Persists correlation before releasing a non-idempotent dispatch permit.
    pub fn persist_request(
        &mut self,
        request: RequestContext,
    ) -> Result<RequestPermit, SessionError> {
        self.require_live(request.session, request.now)?;
        let request_id = self.unique_request_id()?;
        let key = request_tombstone(
            (self.peer, self.epoch, request.session),
            (request_id, request.kind),
        );
        let persisted = self
            .replay
            .persist(&key, TombstoneTime::new(request.now, self.epoch))?;
        self.requests.push((request_id, request.kind));
        Ok(RequestPermit {
            request_id,
            kind: request.kind,
            persisted,
        })
    }

    /// Rejects reuse, including the same ID under another request kind.
    pub fn admit_request_id(
        &mut self,
        request: RequestContext,
        request_id: RequestId,
    ) -> Result<RequestPermit, SessionError> {
        self.require_live(request.session, request.now)?;
        if self.requests.iter().any(|(seen, _)| *seen == request_id) {
            return Err(SessionError::Replay);
        }
        let key = request_tombstone(
            (self.peer, self.epoch, request.session),
            (request_id, request.kind),
        );
        let persisted = self
            .replay
            .persist(&key, TombstoneTime::new(request.now, self.epoch))?;
        self.requests.push((request_id, request.kind));
        Ok(RequestPermit {
            request_id,
            kind: request.kind,
            persisted,
        })
    }

    /// Consumes one local admission-error budget unit.
    pub const fn record_failure(&mut self) -> Result<(), SessionError> {
        if self.failures >= MAX_ADMISSION_FAILURES {
            return Err(SessionError::RateLimited);
        }
        self.failures = self.failures.saturating_add(1);
        Ok(())
    }

    fn require_live(&mut self, id: SessionId, now: u64) -> Result<(), SessionError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.id == id)
            .ok_or(SessionError::Missing)?;
        if now < session.last_activity {
            return Err(SessionError::TimeRegression);
        }
        if now.saturating_sub(session.last_activity) >= IDLE_SECONDS
            || now.saturating_sub(session.created) >= TTL_SECONDS
        {
            return Err(SessionError::Expired);
        }
        session.last_activity = now;
        Ok(())
    }

    fn unique_session_id(&self) -> Result<SessionId, SessionError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 32];
            self.rng.fill(&mut bytes)?;
            let id = SessionId::new(bytes);
            if !self.sessions.iter().any(|session| session.id == id) {
                return Ok(id);
            }
        }
        Err(SessionError::Collision)
    }

    fn unique_request_id(&self) -> Result<RequestId, SessionError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 16];
            self.rng.fill(&mut bytes)?;
            let id = RequestId::new(bytes);
            if !self.requests.iter().any(|(request, _)| *request == id) {
                return Ok(id);
            }
        }
        Err(SessionError::Collision)
    }
}

/// Session admission and replay failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SessionError {
    /// Randomness could not be obtained.
    #[error("secure randomness failed")]
    Random,
    /// A bounded random collision budget was consumed.
    #[error("identifier collision budget exhausted")]
    Collision,
    /// Live session capacity was reached.
    #[error("session capacity reached")]
    Capacity,
    /// Profile epoch is invalid.
    #[error("profile epoch is invalid")]
    Profile,
    /// The session is unknown.
    #[error("session is not live")]
    Missing,
    /// Idle or total lifetime boundary was reached.
    #[error("session expired")]
    Expired,
    /// A replay was observed.
    #[error("request replay rejected")]
    Replay,
    /// Monotonic time moved backwards.
    #[error("monotonic time regressed")]
    TimeRegression,
    /// Local error budget was exhausted.
    #[error("local admission budget exhausted")]
    RateLimited,
    /// Persistent replay state rejected the transition.
    #[error(transparent)]
    State(#[from] StateError),
}
