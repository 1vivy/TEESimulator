use core::fmt;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, MutexGuard, Weak},
};

use thiserror::Error;

use crate::{
    MAX_STATE_BYTES, StateError, StateStore,
    failure_budget_codec::{FailureState, PeerFailures, decode, encode},
    validate_record,
};

const RECORD_KEY: &[u8] = b"rka-peer-failures-v1";
const MAX_PEERS: usize = 32;
/// Previously shipped Task 10 admission-failure threshold.
pub const FAILURE_THRESHOLD: usize = 8;
/// Sliding window derived from the frozen Task 10 120-second session TTL.
pub const FAILURE_WINDOW_SECONDS: u64 = 120;

type NamespaceLocks = HashMap<[u8; 32], Weak<Mutex<()>>>;

static NAMESPACE_LOCKS: LazyLock<Mutex<NamespaceLocks>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Typed source for one candidate's persistent failure-budget namespace.
pub trait FailureBudgetNamespace {
    /// Returns the stable candidate identity bytes used by the shared record.
    fn failure_budget_namespace(&self) -> [u8; 32];
}

impl FailureBudgetNamespace for [u8; 32] {
    fn failure_budget_namespace(&self) -> [u8; 32] {
        *self
    }
}

/// One peer's restart-safe sliding failure budget.
pub struct FailureBudget<'a, S: StateStore> {
    store: &'a S,
    namespace: [u8; 32],
    namespace_lock: Arc<Mutex<()>>,
}

impl<S: StateStore> fmt::Debug for FailureBudget<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FailureBudget([redacted peer budget])")
    }
}

impl<'a, S: StateStore> FailureBudget<'a, S> {
    /// Loads and canonically rewrites the authoritative bounded state.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the namespace witness is a small Copy identity value consumed at admission"
    )]
    pub fn load(
        store: &'a S,
        candidate: impl FailureBudgetNamespace,
        now: u64,
    ) -> Result<Self, FailureBudgetError> {
        let namespace = candidate.failure_budget_namespace();
        let budget = Self {
            store,
            namespace,
            namespace_lock: namespace_lock(namespace),
        };
        {
            let _guard = budget.lock_namespace();
            let state = budget.read_at(now)?;
            budget.flush(&state)?;
        }
        Ok(budget)
    }

    /// Checks the same authoritative state while excluding concurrent failures.
    pub fn admit(&self, now: u64) -> Result<FailureAdmission<'_>, FailureBudgetError> {
        let guard = self.lock_namespace();
        let state = self.read_at(now)?;
        self.flush(&state)?;
        if self.failure_count(&state) >= FAILURE_THRESHOLD {
            return Err(FailureBudgetError::RateLimited);
        }
        Ok(FailureAdmission { _guard: guard })
    }

    /// Persists one failure before returning success to its caller.
    pub fn record(&self, now: u64) -> Result<(), FailureBudgetError> {
        let _guard = self.lock_namespace();
        let mut state = self.read_at(now)?;
        let index = match state
            .peers
            .binary_search_by_key(&self.namespace, |peer| peer.namespace)
        {
            Ok(index) => index,
            Err(index) => {
                if state.peers.len() >= MAX_PEERS {
                    return Err(StateError::Capacity.into());
                }
                state.peers.insert(
                    index,
                    PeerFailures {
                        namespace: self.namespace,
                        timestamps: Vec::with_capacity(FAILURE_THRESHOLD),
                    },
                );
                index
            }
        };
        let peer = state.peers.get_mut(index).ok_or(StateError::Corrupt)?;
        if peer.timestamps.len() >= FAILURE_THRESHOLD {
            self.flush(&state)?;
            return Err(FailureBudgetError::RateLimited);
        }
        peer.timestamps.push(now);
        self.flush(&state)
    }

    fn read_at(&self, now: u64) -> Result<FailureState, FailureBudgetError> {
        let mut bytes = vec![0_u8; MAX_STATE_BYTES];
        let mut state = match self.store.read(RECORD_KEY, &mut bytes) {
            Ok(length) => decode(
                bytes.get(..length).ok_or(StateError::Corrupt)?,
                MAX_PEERS,
                FAILURE_THRESHOLD,
            )?,
            Err(StateError::Missing) => FailureState {
                observed_at: now,
                peers: Vec::with_capacity(MAX_PEERS),
            },
            Err(error) => return Err(error.into()),
        };
        if now < state.observed_at {
            return Err(StateError::TimeRegression.into());
        }
        for peer in &mut state.peers {
            peer.timestamps
                .retain(|timestamp| now.saturating_sub(*timestamp) < FAILURE_WINDOW_SECONDS);
        }
        state.peers.retain(|peer| !peer.timestamps.is_empty());
        state.observed_at = now;
        Ok(state)
    }

    fn failure_count(&self, state: &FailureState) -> usize {
        state
            .peers
            .binary_search_by_key(&self.namespace, |peer| peer.namespace)
            .ok()
            .and_then(|index| state.peers.get(index))
            .map_or(0, |peer| peer.timestamps.len())
    }

    fn flush(&self, state: &FailureState) -> Result<(), FailureBudgetError> {
        let bytes = encode(state);
        validate_record(&bytes)?;
        self.store.replace(RECORD_KEY, &bytes)?;
        Ok(())
    }

    fn lock_namespace(&self) -> MutexGuard<'_, ()> {
        match self.namespace_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Guard proving the budget remained below threshold until permit creation.
pub struct FailureAdmission<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl fmt::Debug for FailureAdmission<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FailureAdmission([redacted budget guard])")
    }
}

/// Failure-budget boundary errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum FailureBudgetError {
    /// The exact peer has exhausted eight failures inside 120 seconds.
    #[error("peer failure budget exhausted")]
    RateLimited,
    /// Persistent state rejected the transition.
    #[error(transparent)]
    State(#[from] StateError),
}

fn namespace_lock(namespace: [u8; 32]) -> Arc<Mutex<()>> {
    let mut locks = match NAMESPACE_LOCKS.lock() {
        Ok(locks) => locks,
        Err(poisoned) => poisoned.into_inner(),
    };
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&namespace).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(namespace, Arc::downgrade(&lock));
    lock
}

#[cfg(test)]
#[path = "failure_budget_tests.rs"]
mod tests;
