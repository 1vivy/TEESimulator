use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::candidate::CandidateId;

use super::{DonorError, lock_depth::DonorLockGuard};

/// Maximum persisted pairing-catalog entries on one donor.
pub const MAX_PAIRED_CANDIDATES_DONOR_WIDE: usize = 32;
/// Maximum simultaneous sessions owned by one candidate.
pub const MAX_LIVE_SESSIONS_PER_CANDIDATE: usize = 1;
/// Maximum simultaneous authenticated sessions on one donor.
pub const MAX_LIVE_SESSIONS_DONOR_WIDE: usize = 4;
/// Maximum retained remote keys owned by one candidate.
pub const MAX_REMOTE_KEYS_PER_CANDIDATE: usize = 4;
/// Maximum retained remote keys across active candidate shards.
pub const MAX_REMOTE_KEYS_DONOR_WIDE: usize = 16;
/// Maximum live operations for one remote key.
pub const MAX_LIVE_OPERATIONS_PER_KEY: usize = 1;
/// Maximum live operations owned by one candidate.
pub const MAX_LIVE_OPERATIONS_PER_CANDIDATE: usize = 1;
/// Maximum live operations across active candidate shards.
pub const MAX_LIVE_OPERATIONS_DONOR_WIDE: usize = 4;
/// Maximum physical TEE calls executing concurrently.
pub const MAX_PHYSICAL_TEE_CALLS_ACTIVE: usize = 1;
/// Maximum outstanding broker commands owned by one candidate.
pub const MAX_BROKER_QUEUE_PER_CANDIDATE: usize = 1;
/// Maximum outstanding broker commands queued donor-wide.
pub const MAX_BROKER_QUEUE_DONOR_WIDE: usize = 4;

#[derive(Debug, Default)]
struct QuotaState {
    sessions: HashSet<CandidateId>,
    remote_keys: usize,
    live_operations: usize,
}

/// Shared donor-wide quota ledger with owned permits.
#[derive(Debug, Default)]
pub struct DonorQuota {
    state: Mutex<QuotaState>,
}

impl DonorQuota {
    /// Creates one shared donor-wide quota ledger.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(super) fn has_remote_key_capacity(&self) -> bool {
        self.lock().remote_keys < MAX_REMOTE_KEYS_DONOR_WIDE
    }

    pub(super) fn has_live_operation_capacity(&self) -> bool {
        self.lock().live_operations < MAX_LIVE_OPERATIONS_DONOR_WIDE
    }

    pub(super) fn acquire_remote_key(self: &Arc<Self>) -> Result<RemoteKeyPermit, DonorError> {
        let mut state = self.lock();
        if state.remote_keys >= MAX_REMOTE_KEYS_DONOR_WIDE {
            return Err(DonorError::Capacity);
        }
        state.remote_keys = state.remote_keys.saturating_add(1);
        drop(state);
        Ok(RemoteKeyPermit {
            quota: Arc::clone(self),
        })
    }

    pub(super) fn acquire_live_operation(
        self: &Arc<Self>,
    ) -> Result<LiveOperationPermit, DonorError> {
        let mut state = self.lock();
        if state.live_operations >= MAX_LIVE_OPERATIONS_DONOR_WIDE {
            return Err(DonorError::Capacity);
        }
        state.live_operations = state.live_operations.saturating_add(1);
        drop(state);
        Ok(LiveOperationPermit {
            quota: Arc::clone(self),
        })
    }

    pub(super) fn acquire_session(
        self: &Arc<Self>,
        candidate: &CandidateId,
    ) -> Result<SessionPermit, DonorError> {
        let mut state = self.lock();
        if state.sessions.contains(candidate) {
            return Err(DonorError::ConcurrentOperation);
        }
        if state.sessions.len() >= MAX_LIVE_SESSIONS_DONOR_WIDE {
            return Err(DonorError::Capacity);
        }
        state.sessions.insert(*candidate);
        drop(state);
        Ok(SessionPermit {
            quota: Arc::clone(self),
            candidate: *candidate,
        })
    }

    fn lock(&self) -> QuotaGuard<'_> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        QuotaGuard {
            state,
            _depth: DonorLockGuard::enter(),
        }
    }
}

struct QuotaGuard<'a> {
    state: MutexGuard<'a, QuotaState>,
    _depth: DonorLockGuard,
}

impl Deref for QuotaGuard<'_> {
    type Target = QuotaState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for QuotaGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

#[derive(Debug)]
pub(super) struct RemoteKeyPermit {
    quota: Arc<DonorQuota>,
}

impl Drop for RemoteKeyPermit {
    fn drop(&mut self) {
        let mut state = self.quota.lock();
        state.remote_keys = state.remote_keys.saturating_sub(1);
    }
}

#[derive(Debug)]
pub(super) struct LiveOperationPermit {
    quota: Arc<DonorQuota>,
}

impl Drop for LiveOperationPermit {
    fn drop(&mut self) {
        let mut state = self.quota.lock();
        state.live_operations = state.live_operations.saturating_sub(1);
    }
}

/// Owned proof that one candidate holds a donor session slot.
#[derive(Debug)]
pub struct SessionPermit {
    quota: Arc<DonorQuota>,
    candidate: CandidateId,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.quota.lock().sessions.remove(&self.candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::DonorQuota;
    use crate::donor::donor_lock_depth;

    #[test]
    fn quota_guard_tracks_and_releases_donor_lock_depth() {
        // Given
        let quota = DonorQuota::default();
        assert_eq!(donor_lock_depth(), 0);

        // When
        {
            let _guard = quota.lock();

            // Then
            assert_eq!(donor_lock_depth(), 1);
        }
        assert_eq!(donor_lock_depth(), 0);
    }
}
