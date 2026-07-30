use rka_protocol::{CborWriter, validate_deterministic_cbor};

use crate::{MAX_STATE_BYTES, StateError, StateStore, validate_record};

const RECORD_KEY: &[u8] = b"rka-replay-v2";
const MAX_TOMBSTONES: usize = 1_024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Tombstone {
    key: Vec<u8>,
    created: TombstoneTime,
}

/// Opaque proof that a replay key was durably persisted.
#[derive(Debug)]
pub struct PersistedTombstone {
    key: Vec<u8>,
}

impl PersistedTombstone {
    /// Returns the canonical tuple bytes without exposing a construction path.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Bounded persistent replay set.
#[derive(Debug)]
pub struct ReplayManager<'a, S: StateStore> {
    store: &'a S,
    entries: Vec<Tombstone>,
    last_time: Option<u64>,
}

impl<'a, S: StateStore> ReplayManager<'a, S> {
    /// Loads the canonical record, failing closed on malformed bytes.
    pub fn load(store: &'a S) -> Result<Self, StateError> {
        let mut bytes = vec![0_u8; MAX_STATE_BYTES];
        let entries = match store.read(RECORD_KEY, &mut bytes) {
            Ok(length) => decode(bytes.get(..length).ok_or(StateError::Corrupt)?)?,
            Err(StateError::Missing) => Vec::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            store,
            entries,
            last_time: None,
        })
    }

    /// Persists a unique key before returning an opaque dispatch permit.
    pub fn persist(
        &mut self,
        key: &[u8],
        created: TombstoneTime,
    ) -> Result<PersistedTombstone, StateError> {
        self.observe_time(created.seconds)?;
        if self.entries.iter().any(|entry| entry.key == key) {
            return Err(StateError::Replay);
        }
        if self.entries.len() >= MAX_TOMBSTONES {
            return Err(StateError::Capacity);
        }
        self.entries.push(Tombstone {
            key: key.to_vec(),
            created,
        });
        if let Err(error) = self.flush() {
            self.entries.pop();
            return Err(error);
        }
        Ok(PersistedTombstone { key: key.to_vec() })
    }

    /// Purges only records old enough in both time and epoch coordinates.
    pub fn purge(&mut self, now: TombstoneTime) -> Result<usize, StateError> {
        self.observe_time(now.seconds)?;
        let before = self.entries.len();
        self.entries.retain(|entry| {
            let age = now.seconds.saturating_sub(entry.created.seconds);
            let epochs = now.epoch.saturating_sub(entry.created.epoch);
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

    fn flush(&self) -> Result<(), StateError> {
        let bytes = encode(&self.entries);
        validate_record(&bytes)?;
        self.store.replace(RECORD_KEY, &bytes)
    }
}

fn encode(entries: &[Tombstone]) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(entries.len().saturating_mul(80));
    writer.array(entries.len());
    for entry in entries {
        writer.array(3);
        writer.unsigned(entry.created.seconds);
        writer.unsigned(entry.created.epoch);
        writer.bytes(&entry.key);
    }
    writer.finish()
}

fn decode(bytes: &[u8]) -> Result<Vec<Tombstone>, StateError> {
    validate_deterministic_cbor(bytes).map_err(|_| StateError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array()?;
    if count > MAX_TOMBSTONES {
        return Err(StateError::Corrupt);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array()? != 3 {
            return Err(StateError::Corrupt);
        }
        let created = TombstoneTime {
            seconds: decoder.unsigned()?,
            epoch: decoder.unsigned()?,
        };
        let key = decoder.bytes()?.to_vec();
        if key.is_empty() || entries.iter().any(|entry: &Tombstone| entry.key == key) {
            return Err(StateError::Corrupt);
        }
        entries.push(Tombstone { key, created });
    }
    if decoder.complete() {
        Ok(entries)
    } else {
        Err(StateError::Corrupt)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array(&mut self) -> Result<usize, StateError> {
        let (major, length) = self.header()?;
        if major != 4 {
            return Err(StateError::Corrupt);
        }
        usize::try_from(length).map_err(|_| StateError::Corrupt)
    }

    fn unsigned(&mut self) -> Result<u64, StateError> {
        let (major, value) = self.header()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(StateError::Corrupt)
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], StateError> {
        let (major, length) = self.header()?;
        if major != 2 {
            return Err(StateError::Corrupt);
        }
        self.take(usize::try_from(length).map_err(|_| StateError::Corrupt)?)
    }

    const fn complete(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn header(&mut self) -> Result<(u8, u64), StateError> {
        let initial = *self.bytes.get(self.offset).ok_or(StateError::Corrupt)?;
        self.offset = self.offset.checked_add(1).ok_or(StateError::Corrupt)?;
        let additional = initial & 0x1f;
        let value = match additional {
            value @ 0..=23 => u64::from(value),
            24 => self.argument(1, 24)?,
            25 => self.argument(2, 256)?,
            26 => self.argument(4, 65_536)?,
            27 => self.argument(8, 4_294_967_296)?,
            _ => return Err(StateError::Corrupt),
        };
        Ok((initial >> 5, value))
    }

    fn argument(&mut self, width: usize, minimum: u64) -> Result<u64, StateError> {
        let value = self
            .take(width)?
            .iter()
            .fold(0_u64, |current, byte| (current << 8) | u64::from(*byte));
        if value < minimum {
            return Err(StateError::Corrupt);
        }
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StateError> {
        let end = self.offset.checked_add(length).ok_or(StateError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StateError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }
}
