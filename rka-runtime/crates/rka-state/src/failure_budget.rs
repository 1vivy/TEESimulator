use core::fmt;
use std::sync::{Mutex, MutexGuard};

use rka_protocol::{CborWriter, validate_deterministic_cbor};
use thiserror::Error;

use crate::{MAX_STATE_BYTES, StateError, StateStore, replay_codec::Decoder, validate_record};

const RECORD_KEY: &[u8] = b"rka-peer-failures-v1";
const MAX_PEERS: usize = 32;
/// Previously shipped Task 10 admission-failure threshold.
pub const FAILURE_THRESHOLD: usize = 8;
/// Sliding window derived from the frozen Task 10 120-second session TTL.
pub const FAILURE_WINDOW_SECONDS: u64 = 120;

static FAILURE_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = lock();
        let budget = Self {
            store,
            namespace: candidate.failure_budget_namespace(),
        };
        let state = budget.read_at(now)?;
        budget.flush(&state)?;
        Ok(budget)
    }

    /// Checks the same authoritative state while excluding concurrent failures.
    pub fn admit(&self, now: u64) -> Result<FailureAdmission, FailureBudgetError> {
        let guard = lock();
        let state = self.read_at(now)?;
        self.flush(&state)?;
        if self.failure_count(&state) >= FAILURE_THRESHOLD {
            return Err(FailureBudgetError::RateLimited);
        }
        Ok(FailureAdmission { _guard: guard })
    }

    /// Persists one failure before returning success to its caller.
    pub fn record(&self, now: u64) -> Result<(), FailureBudgetError> {
        let _guard = lock();
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
}

/// Guard proving the budget remained below threshold until permit creation.
pub struct FailureAdmission {
    _guard: MutexGuard<'static, ()>,
}

impl fmt::Debug for FailureAdmission {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerFailures {
    namespace: [u8; 32],
    timestamps: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FailureState {
    observed_at: u64,
    peers: Vec<PeerFailures>,
}

fn encode(state: &FailureState) -> Vec<u8> {
    let timestamp_count = state
        .peers
        .iter()
        .map(|peer| peer.timestamps.len())
        .sum::<usize>();
    let mut writer = CborWriter::with_capacity(
        16_usize
            .saturating_add(state.peers.len().saturating_mul(40))
            .saturating_add(timestamp_count.saturating_mul(9)),
    );
    writer.array(2);
    writer.unsigned(state.observed_at);
    writer.array(state.peers.len());
    for peer in &state.peers {
        writer.array(2);
        writer.bytes(&peer.namespace);
        writer.array(peer.timestamps.len());
        for timestamp in &peer.timestamps {
            writer.unsigned(*timestamp);
        }
    }
    writer.finish()
}

fn decode(
    bytes: &[u8],
    maximum_peers: usize,
    maximum_timestamps: usize,
) -> Result<FailureState, StateError> {
    validate_deterministic_cbor(bytes).map_err(|_| StateError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array()? != 2 {
        return Err(StateError::Corrupt);
    }
    let observed_at = decoder.unsigned()?;
    let count = decoder.array()?;
    if count > maximum_peers {
        return Err(StateError::Corrupt);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array()? != 2 {
            return Err(StateError::Corrupt);
        }
        let namespace = decoder
            .bytes()?
            .try_into()
            .map_err(|_| StateError::Corrupt)?;
        let timestamp_count = decoder.array()?;
        if timestamp_count == 0 || timestamp_count > maximum_timestamps {
            return Err(StateError::Corrupt);
        }
        let mut timestamps = Vec::with_capacity(timestamp_count);
        for _ in 0..timestamp_count {
            let timestamp = decoder.unsigned()?;
            if timestamp > observed_at
                || timestamps
                    .last()
                    .is_some_and(|previous| timestamp < *previous)
            {
                return Err(StateError::Corrupt);
            }
            timestamps.push(timestamp);
        }
        if peers
            .last()
            .is_some_and(|previous: &PeerFailures| previous.namespace >= namespace)
        {
            return Err(StateError::Corrupt);
        }
        peers.push(PeerFailures {
            namespace,
            timestamps,
        });
    }
    if !decoder.complete() {
        return Err(StateError::Corrupt);
    }
    Ok(FailureState { observed_at, peers })
}

fn lock() -> MutexGuard<'static, ()> {
    match FAILURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
#[path = "failure_budget_tests.rs"]
mod tests;
