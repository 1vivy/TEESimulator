use crate::{
    MAX_STATE_BYTES, StateError, StateStore,
    replay_codec::{ReplayNamespace, Tombstone, decode, encode},
    validate_record,
};

const RECORD_KEY: &[u8] = b"rka-replay-v2";
const MAX_TOMBSTONES: usize = 1_024;
const MAX_CANDIDATES: usize = 32;
const MAX_DONOR_REPLAY_BYTES: usize = MAX_STATE_BYTES * MAX_CANDIDATES;

/// Monotonic creation coordinates retained with a replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TombstoneTime {
    /// Donor monotonic seconds.
    pub seconds: u64,
    /// Active public-profile epoch.
    pub epoch: u64,
}

impl TombstoneTime {
    /// Creates monotonic replay-retention coordinates.
    #[must_use]
    pub const fn new(seconds: u64, epoch: u64) -> Self {
        Self { seconds, epoch }
    }
}

/// Opaque proof that a replay key was durably persisted.
pub struct PersistedTombstone {
    key: Vec<u8>,
}

impl fmt::Debug for PersistedTombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedTombstone([redacted replay key])")
    }
}

impl PersistedTombstone {
    /// Returns the canonical tuple bytes without exposing a construction path.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Bounded persistent replay set.
pub struct ReplayManager<'a, S: StateStore> {
    store: &'a S,
    entries: Vec<Tombstone>,
    last_time: Option<u64>,
    persisted_bytes: usize,
}

impl<S: StateStore> fmt::Debug for ReplayManager<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayManager")
            .field("retained", &self.entries.len())
            .finish()
    }
}

impl<'a, S: StateStore> ReplayManager<'a, S> {
    /// Loads the canonical record, failing closed on malformed bytes.
    pub fn load(store: &'a S) -> Result<Self, StateError> {
        let mut bytes = vec![0_u8; MAX_STATE_BYTES];
        let (entries, persisted_bytes) = match store.read(RECORD_KEY, &mut bytes) {
            Ok(length) => (
                decode(
                    bytes.get(..length).ok_or(StateError::Corrupt)?,
                    MAX_TOMBSTONES,
                )?,
                length,
            ),
            Err(StateError::Missing) => (Vec::new(), 0),
            Err(error) => return Err(error),
        };
        Ok(Self {
            store,
            entries,
            last_time: None,
            persisted_bytes,
        })
    }

    /// Persists a unique key before returning an opaque dispatch permit.
    pub fn persist(
        &mut self,
        key: &[u8],
        created: TombstoneTime,
    ) -> Result<PersistedTombstone, StateError> {
        self.persist_in_namespace(
            ReplayRecordRef {
                key,
                namespace: ReplayNamespace::Opaque,
                id: &[],
            },
            created,
        )
    }

    /// Persists a session tombstone retaining its raw opaque identifier.
    pub fn persist_session(
        &mut self,
        record: (&[u8], [u8; 32]),
        created: TombstoneTime,
    ) -> Result<PersistedTombstone, StateError> {
        self.persist_in_namespace(
            ReplayRecordRef {
                key: record.0,
                namespace: ReplayNamespace::Session,
                id: &record.1,
            },
            created,
        )
    }

    /// Persists a request tombstone retaining its raw opaque identifier.
    pub fn persist_request(
        &mut self,
        record: (&[u8], [u8; 16]),
        created: TombstoneTime,
    ) -> Result<PersistedTombstone, StateError> {
        self.persist_in_namespace(
            ReplayRecordRef {
                key: record.0,
                namespace: ReplayNamespace::Request,
                id: &record.1,
            },
            created,
        )
    }

    /// Reports whether a session identifier remains retained after restart.
    #[must_use]
    pub fn session_id_retained(&self, session_id: [u8; 32]) -> bool {
        self.retained(ReplayNamespace::Session, &session_id)
    }

    /// Reports whether a request identifier remains retained under any kind.
    #[must_use]
    pub fn request_id_retained(&self, request_id: [u8; 16]) -> bool {
        self.retained(ReplayNamespace::Request, &request_id)
    }

    fn persist_in_namespace(
        &mut self,
        record: ReplayRecordRef<'_>,
        created: TombstoneTime,
    ) -> Result<PersistedTombstone, StateError> {
        self.observe_time(created.seconds)?;
        if self.entries.iter().any(|entry| {
            entry.key == record.key
                || (record.namespace != ReplayNamespace::Opaque
                    && entry.namespace == record.namespace
                    && entry.id == record.id)
        }) {
            return Err(StateError::Replay);
        }
        if self.entries.len() >= MAX_TOMBSTONES {
            return Err(StateError::Capacity);
        }
        self.entries.push(Tombstone {
            key: record.key.to_vec(),
            seconds: created.seconds,
            epoch: created.epoch,
            namespace: record.namespace,
            id: record.id.to_vec(),
        });
        if let Err(error) = self.flush() {
            self.entries.pop();
            return Err(error);
        }
        Ok(PersistedTombstone {
            key: record.key.to_vec(),
        })
    }

    /// Purges only records old enough in both time and epoch coordinates.
    pub fn purge(&mut self, now: TombstoneTime) -> Result<usize, StateError> {
        self.observe_time(now.seconds)?;
        let before = self.entries.len();
        self.entries.retain(|entry| {
            let age = now.seconds.saturating_sub(entry.seconds);
            let epochs = now.epoch.saturating_sub(entry.epoch);
            age < rka_protocol::REPLAY_MIN_SECONDS
                || epochs < rka_protocol::REPLAY_MIN_PROFILE_EPOCHS
        });
        let removed = before.saturating_sub(self.entries.len());
        if removed > 0 {
            self.flush()?;
        }
        Ok(removed)
    }

    fn observe_time(&mut self, now: u64) -> Result<(), StateError> {
        if self.last_time.is_some_and(|previous| now < previous) {
            return Err(StateError::TimeRegression);
        }
        self.last_time = Some(now);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StateError> {
        let bytes = encode(&self.entries);
        validate_record(&bytes)?;
        let donor_bytes = self.store.donor_replay_bytes()?;
        let projected = donor_bytes
            .saturating_sub(self.persisted_bytes)
            .checked_add(bytes.len())
            .ok_or(StateError::Capacity)?;
        if projected > MAX_DONOR_REPLAY_BYTES {
            return Err(StateError::Capacity);
        }
        self.store.replace(RECORD_KEY, &bytes)?;
        self.persisted_bytes = bytes.len();
        Ok(())
    }

    fn retained(&self, namespace: ReplayNamespace, id: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.namespace == namespace && entry.id == id)
    }
}

#[derive(Clone, Copy)]
struct ReplayRecordRef<'a> {
    key: &'a [u8],
    namespace: ReplayNamespace,
    id: &'a [u8],
}
use core::fmt;

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
