use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use super::{FailureBudget, FailureBudgetError, MAX_PEERS};
use crate::{StateError, StateStore};

#[test]
fn exhausting_one_candidate_budget_does_not_rate_limit_another()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let store = MemoryStore::default();
    let candidate_a = FailureBudget::load(&store, [0x0a; 32], 1)?;
    let candidate_b = FailureBudget::load(&store, [0x0b; 32], 1)?;
    for _ in 0..8 {
        candidate_a.record(1)?;
    }

    // When
    let exhausted = matches!(candidate_a.admit(1), Err(FailureBudgetError::RateLimited));
    let independent = candidate_b.admit(1);

    // Then
    assert!(exhausted);
    assert!(independent.is_ok());
    drop(independent);
    for value in 0..MAX_PEERS {
        if value == 10 {
            continue;
        }
        let namespace = namespace(value)?;
        FailureBudget::load(&store, namespace, 1)?.record(1)?;
    }
    let thirty_third = FailureBudget::load(&store, [0xff; 32], 1)?.record(1);
    assert!(matches!(
        thirty_third,
        Err(FailureBudgetError::State(StateError::Capacity))
    ));
    Ok(())
}

#[test]
fn slow_persistence_for_one_namespace_does_not_block_another_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let store = Arc::new(BlockingReplaceStore {
        calls: AtomicUsize::new(0),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let store_a = Arc::clone(&store);
    let candidate_a =
        std::thread::spawn(move || FailureBudget::load(&*store_a, [0x0a; 32], 1).is_ok());
    entered_rx.recv()?;
    let store_b = Arc::clone(&store);
    let (candidate_b_tx, candidate_b_rx) = mpsc::channel();

    // When
    let candidate_b = std::thread::spawn(move || {
        candidate_b_tx.send(FailureBudget::load(&*store_b, [0x0b; 32], 1).is_ok())
    });
    let candidate_b_completed = candidate_b_rx.recv_timeout(Duration::from_secs(1))?;

    // Then
    assert!(candidate_b_completed);
    release_tx.send(())?;
    assert!(
        candidate_a
            .join()
            .map_err(|_| "candidate A failure-budget thread failed")?
    );
    candidate_b
        .join()
        .map_err(|_| "candidate B failure-budget thread failed")??;
    Ok(())
}

fn namespace(value: usize) -> Result<[u8; 32], StateError> {
    let byte = u8::try_from(value).map_err(|_| StateError::Capacity)?;
    Ok([byte; 32])
}

#[derive(Default)]
struct MemoryStore(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);

impl StateStore for MemoryStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let records = self.0.lock().map_err(|_| StateError::Storage)?;
        let value = records.get(key).ok_or(StateError::Missing)?.clone();
        drop(records);
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.0
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

struct BlockingReplaceStore {
    calls: AtomicUsize,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl StateStore for BlockingReplaceStore {
    fn read(&self, _key: &[u8], _output: &mut [u8]) -> Result<usize, StateError> {
        Err(StateError::Missing)
    }

    fn replace(&self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.send(()).map_err(|_| StateError::Storage)?;
            self.release
                .lock()
                .map_err(|_| StateError::Storage)?
                .recv()
                .map_err(|_| StateError::Storage)?;
        }
        Ok(())
    }
}
