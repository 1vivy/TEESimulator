use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use super::{MAX_DONOR_REPLAY_BYTES, MAX_TOMBSTONES, ReplayManager, TombstoneTime};
use crate::{StateError, StateStore};

#[test]
fn a_session_id_retained_for_one_candidate_is_not_retained_for_another()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let disk = Mutex::new(BTreeMap::new());
    let candidate_a = RootedStore::new(Path::new("candidates/aa"), &disk);
    let candidate_b = RootedStore::new(Path::new("candidates/bb"), &disk);
    let session = [0x55; 32];
    let mut replay_a = ReplayManager::load(&candidate_a)?;
    replay_a.persist_session((b"session-a", session), TombstoneTime::new(1, 1))?;

    // When
    let mut reopened_a = ReplayManager::load(&candidate_a)?;
    let mut reopened_b = ReplayManager::load(&candidate_b)?;

    // Then
    assert!(reopened_a.session_id_retained(session));
    assert!(!reopened_b.session_id_retained(session));
    fill_to_ceiling(&mut reopened_a, b'a', 2)?;
    fill_to_ceiling(&mut reopened_b, b'b', 1)?;
    assert!(matches!(
        reopened_a.persist(b"candidate-a-overflow", TombstoneTime::new(2, 1)),
        Err(StateError::Capacity)
    ));
    assert!(matches!(
        reopened_b.persist(b"candidate-b-overflow", TombstoneTime::new(2, 1)),
        Err(StateError::Capacity)
    ));
    Ok(())
}

#[test]
fn donor_wide_disk_ceiling_is_checked_before_persist() -> Result<(), StateError> {
    // Given
    let store = FullDonorStore;
    let mut replay = ReplayManager::load(&store)?;

    // When
    let result = replay.persist(b"new", TombstoneTime::new(1, 1));

    // Then
    assert!(matches!(result, Err(StateError::Capacity)));
    Ok(())
}

struct FullDonorStore;

impl StateStore for FullDonorStore {
    fn read(&self, _key: &[u8], _output: &mut [u8]) -> Result<usize, StateError> {
        Err(StateError::Missing)
    }

    fn replace(&self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(StateError::Storage)
    }

    fn donor_replay_bytes(&self) -> Result<usize, StateError> {
        Ok(MAX_DONOR_REPLAY_BYTES)
    }
}

fn fill_to_ceiling(
    replay: &mut ReplayManager<'_, RootedStore<'_>>,
    prefix: u8,
    first: usize,
) -> Result<(), StateError> {
    for value in first..=MAX_TOMBSTONES {
        let high = u8::try_from(value >> 8).map_err(|_| StateError::Capacity)?;
        let low = u8::try_from(value & 0xff).map_err(|_| StateError::Capacity)?;
        let key = [prefix, high, low];
        replay.persist(&key, TombstoneTime::new(1, 1))?;
    }
    Ok(())
}

struct RootedStore<'a> {
    root: PathBuf,
    disk: &'a Mutex<BTreeMap<PathBuf, Vec<u8>>>,
}

impl<'a> RootedStore<'a> {
    fn new(root: &Path, disk: &'a Mutex<BTreeMap<PathBuf, Vec<u8>>>) -> Self {
        Self {
            root: root.to_path_buf(),
            disk,
        }
    }

    fn path(&self, key: &[u8]) -> PathBuf {
        self.root.join(String::from_utf8_lossy(key).as_ref())
    }
}

impl StateStore for RootedStore<'_> {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let disk = self.disk.lock().map_err(|_| StateError::Storage)?;
        let value = disk
            .get(&self.path(key))
            .ok_or(StateError::Missing)?
            .clone();
        drop(disk);
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.disk
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(self.path(key), value.to_vec());
        Ok(())
    }
}
