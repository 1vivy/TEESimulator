use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use rka_protocol::SessionId;
use thiserror::Error;

const MAX_SESSIONS: usize = 4;
const IDLE_SECONDS: u64 = 30;
const TTL_SECONDS: u64 = 120;

#[derive(Debug)]
struct SessionRecord {
    id: SessionId,
    created: u64,
    last_activity: u64,
}

#[derive(Debug)]
struct LifecycleState {
    sessions: Vec<SessionRecord>,
    draining: bool,
}

/// Shared authority for session admission and profile draining.
#[derive(Clone)]
pub struct SessionLifecycle {
    inner: Arc<Mutex<LifecycleState>>,
}

impl SessionLifecycle {
    /// Creates one empty lifecycle authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LifecycleState {
                sessions: Vec::with_capacity(MAX_SESSIONS),
                draining: false,
            })),
        }
    }

    pub(crate) fn acquire(
        &self,
        admission: (SessionId, [u8; 32], u64),
    ) -> Result<LiveSessionLease, LifecycleError> {
        let (id, candidate_nonce, now) = admission;
        let mut state = lock(&self.inner);
        if state.draining {
            return Err(LifecycleError::Draining);
        }
        if state.sessions.len() >= MAX_SESSIONS {
            return Err(LifecycleError::Capacity);
        }
        if state.sessions.iter().any(|session| session.id == id) {
            return Err(LifecycleError::Duplicate);
        }
        state.sessions.push(SessionRecord {
            id,
            created: now,
            last_activity: now,
        });
        drop(state);
        Ok(LiveSessionLease {
            lifecycle: self.clone(),
            id,
            candidate_nonce,
            active: true,
        })
    }

    pub(crate) fn check_admission(&self) -> Result<(), LifecycleError> {
        let state = lock(&self.inner);
        if state.draining {
            Err(LifecycleError::Draining)
        } else if state.sessions.len() >= MAX_SESSIONS {
            Err(LifecycleError::Capacity)
        } else {
            Ok(())
        }
    }

    pub(crate) fn touch(&self, id: SessionId, now: u64) -> Result<(), LifecycleError> {
        let mut state = lock(&self.inner);
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.id == id)
            .ok_or(LifecycleError::Missing)?;
        if now < session.last_activity {
            return Err(LifecycleError::TimeRegression);
        }
        if now.saturating_sub(session.last_activity) >= IDLE_SECONDS
            || now.saturating_sub(session.created) >= TTL_SECONDS
        {
            return Err(LifecycleError::Expired);
        }
        session.last_activity = now;
        drop(state);
        Ok(())
    }

    pub(crate) fn contains(&self, id: SessionId) -> bool {
        lock(&self.inner)
            .sessions
            .iter()
            .any(|session| session.id == id)
    }

    pub(crate) fn start_draining(&self) {
        lock(&self.inner).draining = true;
    }

    pub(crate) fn has_live_sessions(&self) -> bool {
        !lock(&self.inner).sessions.is_empty()
    }

    pub(crate) fn finish_rotation(&self) {
        lock(&self.inner).draining = false;
    }

    fn release(&self, id: SessionId) {
        let mut state = lock(&self.inner);
        if let Some(index) = state.sessions.iter().position(|session| session.id == id) {
            state.sessions.swap_remove(index);
        }
    }
}

impl Default for SessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionLifecycle([redacted session registry])")
    }
}

/// Opaque RAII authority for one admitted live session.
pub struct LiveSessionLease {
    lifecycle: SessionLifecycle,
    id: SessionId,
    candidate_nonce: [u8; 32],
    active: bool,
}

impl LiveSessionLease {
    /// Returns the candidate-owned session identifier.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Returns the candidate nonce, distinct from the session identifier.
    #[must_use]
    pub const fn candidate_nonce(&self) -> [u8; 32] {
        self.candidate_nonce
    }

    /// Releases this live-session authority exactly once.
    pub fn close(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if self.active {
            self.lifecycle.release(self.id);
            self.active = false;
        }
    }
}

impl Drop for LiveSessionLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl fmt::Debug for LiveSessionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveSessionLease([redacted live session])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[doc(hidden)]
#[non_exhaustive]
pub enum LifecycleError {
    #[error("profile is draining")]
    Draining,
    #[error("session capacity reached")]
    Capacity,
    #[error("session identifier is already live")]
    Duplicate,
    #[error("session is not live")]
    Missing,
    #[error("session expired")]
    Expired,
    #[error("monotonic time regressed")]
    TimeRegression,
}

fn lock(inner: &Mutex<LifecycleState>) -> MutexGuard<'_, LifecycleState> {
    match inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
