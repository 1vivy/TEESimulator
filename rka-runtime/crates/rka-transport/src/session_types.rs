use core::fmt;

use ring::rand::{SecureRandom, SystemRandom};
use rka_protocol::{MessageKind, PeerSpkiHash, RequestId, SessionId};
use rka_state::{PersistedTombstone, StateError};
use thiserror::Error;

/// Fixed paired-peer coordinates for a session manager.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct SessionScope {
    pub(crate) peer: PeerSpkiHash,
    pub(crate) epoch: u64,
}

impl SessionScope {
    /// Creates nonzero-epoch peer coordinates.
    #[must_use]
    pub const fn new(peer: PeerSpkiHash, epoch: u64) -> Self {
        Self { peer, epoch }
    }
}

impl fmt::Debug for SessionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionScope([redacted peer coordinates])")
    }
}

/// Correlation and time for one candidate-generated request.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestContext {
    pub(crate) session: SessionId,
    pub(crate) kind: MessageKind,
    pub(crate) now: u64,
}

impl RequestContext {
    /// Creates request coordinates under one live session.
    #[must_use]
    pub const fn new(session: SessionId, kind: MessageKind, now: u64) -> Self {
        Self { session, kind, now }
    }
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestContext([redacted request coordinates])")
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

/// Persisted request authority with immutable response correlation.
pub struct PendingRequest {
    request_id: RequestId,
    terminal: TerminalPolicy,
    sequence: u32,
    persisted: PersistedTombstone,
}

impl PendingRequest {
    /// Returns the exact response identifier and sequence.
    #[must_use]
    pub const fn coordinates(&self) -> (RequestId, u32) {
        (self.request_id, self.sequence)
    }

    /// Returns the persisted canonical request tuple.
    #[must_use]
    pub fn replay_key(&self) -> &[u8] {
        self.persisted.key()
    }

    /// Consumes the request only when every response coordinate matches.
    pub fn accept(self, response: ResponseContext) -> Result<AcceptedResponse, SessionError> {
        let ResponseContext {
            request_id,
            terminal,
            sequence,
        } = response;
        if request_id != self.request_id
            || !self.terminal.accepts(terminal)
            || sequence != self.sequence
        {
            return Err(SessionError::Correlation);
        }
        Ok(AcceptedResponse {
            _persisted: self.persisted,
        })
    }

    pub(crate) const fn new(
        correlation: (RequestId, MessageKind, MessageKind, u32),
        persisted: PersistedTombstone,
    ) -> Self {
        let (request_id, request_kind, success_kind, sequence) = correlation;
        Self {
            request_id,
            terminal: TerminalPolicy {
                request_kind,
                success_kind,
            },
            sequence,
            persisted,
        }
    }
}

impl fmt::Debug for PendingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingRequest([redacted correlation])")
    }
}

#[derive(Clone, Copy)]
struct TerminalPolicy {
    request_kind: MessageKind,
    success_kind: MessageKind,
}

impl TerminalPolicy {
    fn accepts(self, terminal: ResponseTerminal) -> bool {
        match terminal {
            ResponseTerminal::Success(kind) => kind == self.success_kind,
            ResponseTerminal::Error(triggering) => {
                self.request_kind != MessageKind::Hello && triggering == self.request_kind
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ResponseTerminal {
    Success(MessageKind),
    Error(MessageKind),
}

/// Opaque coordinates parsed from one terminal response frame.
#[derive(Clone, Copy)]
pub struct ResponseContext {
    request_id: RequestId,
    terminal: ResponseTerminal,
    sequence: u32,
}

impl ResponseContext {
    /// Creates coordinates for one successful response frame.
    #[must_use]
    pub const fn success(request_id: RequestId, kind: MessageKind, sequence: u32) -> Self {
        Self {
            request_id,
            terminal: ResponseTerminal::Success(kind),
            sequence,
        }
    }

    /// Creates coordinates for an ERROR naming its triggering request kind.
    #[must_use]
    pub const fn protocol_error(
        request_id: RequestId,
        triggering: MessageKind,
        sequence: u32,
    ) -> Self {
        Self {
            request_id,
            terminal: ResponseTerminal::Error(triggering),
            sequence,
        }
    }
}

impl fmt::Debug for ResponseContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseContext([redacted correlation])")
    }
}

/// Opaque proof that an exact pending response was accepted.
pub struct AcceptedResponse {
    _persisted: PersistedTombstone,
}

impl fmt::Debug for AcceptedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedResponse([redacted correlation])")
    }
}

/// Session admission, replay, and correlation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SessionError {
    /// Randomness could not be obtained.
    #[error("secure randomness failed")]
    Random,
    /// The finite collision retry budget was exhausted.
    #[error("identifier collision retry budget exhausted")]
    RandomExhausted,
    /// Live session or sequence capacity was reached.
    #[error("session capacity reached")]
    Capacity,
    /// Profile rotation is draining live sessions.
    #[error("profile is draining")]
    Draining,
    /// Profile epoch is invalid.
    #[error("profile epoch is invalid")]
    Profile,
    /// The session is unknown.
    #[error("session is not live")]
    Missing,
    /// Idle or total lifetime boundary was reached.
    #[error("session expired")]
    Expired,
    /// A retained identifier was observed again.
    #[error("request replay rejected")]
    Replay,
    /// Response identifier, kind, or sequence did not match.
    #[error("response correlation rejected")]
    Correlation,
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
