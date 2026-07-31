use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
};

use rka_protocol::{CborWriter, PeerSpkiHash};
use rka_state::{StateError, StateStore};

use super::{CsRng, SessionError, SessionLifecycle, SessionManager, SessionScope};

const FAILURE_KEY: &[u8] = b"rka-peer-failures-v1";

#[derive(Default)]
struct TestStore {
    records: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    fail_replace: AtomicBool,
}

impl TestStore {
    fn record(&self) -> Result<Vec<u8>, StateError> {
        self.records
            .lock()
            .map_err(|_| StateError::Storage)?
            .get(FAILURE_KEY)
            .cloned()
            .ok_or(StateError::Missing)
    }

    fn inject(&self, value: Vec<u8>) -> Result<(), StateError> {
        self.records
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(FAILURE_KEY.to_vec(), value);
        Ok(())
    }
}

impl StateStore for TestStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .records
            .lock()
            .map_err(|_| StateError::Storage)?
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        let maximum = output.len();
        let target = output
            .get_mut(..value.len())
            .ok_or(StateError::RecordTooLarge {
                actual: value.len(),
                maximum,
            })?;
        target.copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        if self.fail_replace.load(Ordering::SeqCst) {
            return Err(StateError::Storage);
        }
        self.records
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

struct CountingRng {
    next: AtomicU8,
    calls: Arc<AtomicUsize>,
}

impl CountingRng {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            next: AtomicU8::new(1),
            calls,
        }
    }
}

impl CsRng for CountingRng {
    fn fill(&self, output: &mut [u8]) -> Result<(), SessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        output.fill(value);
        Ok(())
    }
}

fn manager(
    store: &TestStore,
    coordinates: (u8, u64),
    calls: Arc<AtomicUsize>,
) -> Result<SessionManager<'_, TestStore, CountingRng>, SessionError> {
    let (peer, now) = coordinates;
    SessionManager::load(
        store,
        CountingRng::new(calls),
        (
            SessionScope::new(PeerSpkiHash::new([peer; 32]), 7),
            SessionLifecycle::new(),
            now,
        ),
    )
}

#[test]
fn persistent_budget_restart_expiry_and_peer_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let store = TestStore::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let first = manager(&store, (0x41, 100), Arc::clone(&calls))?;
    for _ in 0..8 {
        first.record_failure(100)?;
    }
    assert_eq!(first.record_failure(100), Err(SessionError::RateLimited));

    let mut other = manager(&store, (0x42, 100), Arc::clone(&calls))?;
    let _other_lease = other.open_candidate(100)?;
    let before_expiry = manager(&store, (0x41, 219), Arc::clone(&calls))?;
    assert_eq!(
        before_expiry.record_failure(219),
        Err(SessionError::RateLimited)
    );

    let mut at_expiry = manager(&store, (0x41, 220), Arc::clone(&calls))?;
    at_expiry.record_failure(220)?;
    let _lease = at_expiry.open_candidate(220)?;
    assert!(calls.load(Ordering::SeqCst) >= 4);
    Ok(())
}

#[test]
fn clock_and_encoded_state_mutations_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let store = TestStore::default();
    let calls = Arc::new(AtomicUsize::new(0));
    manager(&store, (0x51, 500), Arc::clone(&calls))?.record_failure(500)?;
    assert!(matches!(
        manager(&store, (0x51, 499), Arc::clone(&calls)),
        Err(SessionError::State(StateError::TimeRegression))
    ));

    let mut future = CborWriter::with_capacity(16);
    future.array(2);
    future.unsigned(u64::MAX);
    future.array(0);
    store.inject(future.finish())?;
    assert!(matches!(
        manager(&store, (0x51, 500), Arc::clone(&calls)),
        Err(SessionError::State(StateError::TimeRegression))
    ));

    store.inject(vec![0x82, 0x18, 0x01, 0x80])?;
    assert!(matches!(
        manager(&store, (0x51, 500), Arc::clone(&calls)),
        Err(SessionError::State(StateError::Corrupt))
    ));
    store.inject(duplicate_peer_record())?;
    assert!(matches!(
        manager(&store, (0x51, 500), calls),
        Err(SessionError::State(StateError::Corrupt))
    ));
    Ok(())
}

#[test]
fn persistence_failure_precedes_budget_or_session_permit() -> Result<(), Box<dyn std::error::Error>>
{
    let store = TestStore::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut first = manager(&store, (0x61, 10), Arc::clone(&calls))?;
    store.fail_replace.store(true, Ordering::SeqCst);
    assert_eq!(
        first.record_failure(10),
        Err(SessionError::State(StateError::Storage))
    );
    assert!(matches!(
        first.open_candidate(10),
        Err(SessionError::State(StateError::Storage))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    store.fail_replace.store(false, Ordering::SeqCst);
    let restored = manager(&store, (0x61, 10), calls)?;
    for _ in 0..8 {
        restored.record_failure(10)?;
    }
    assert_eq!(restored.record_failure(10), Err(SessionError::RateLimited));
    Ok(())
}

#[test]
fn concurrent_recorders_commit_exactly_the_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let store = TestStore::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let _initialized = manager(&store, (0x71, 1_000), Arc::clone(&calls))?;
    let results = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let results = &results;
            let store = &store;
            let calls = Arc::clone(&calls);
            scope.spawn(move || {
                let result = manager(store, (0x71, 1_000), calls)
                    .and_then(|budget| budget.record_failure(1_000));
                if let Ok(mut captured) = results.lock() {
                    captured.push(result);
                }
            });
        }
    });
    let captured = results.into_inner().map_err(|_| StateError::Storage)?;
    assert_eq!(captured.iter().filter(|result| result.is_ok()).count(), 8);
    assert_eq!(
        captured
            .iter()
            .filter(|result| **result == Err(SessionError::RateLimited))
            .count(),
        8
    );
    assert_eq!(
        manager(&store, (0x71, 1_001), calls)?.record_failure(1_001),
        Err(SessionError::RateLimited)
    );
    Ok(())
}

#[test]
fn peer_count_storage_and_redaction_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let store = TestStore::default();
    let calls = Arc::new(AtomicUsize::new(0));
    for peer in 1..=32 {
        manager(&store, (peer, 2_000), Arc::clone(&calls))?.record_failure(2_000)?;
    }
    assert!(matches!(
        manager(&store, (33, 2_000), Arc::clone(&calls))?.record_failure(2_000),
        Err(SessionError::State(StateError::Capacity))
    ));
    let record = store.record()?;
    assert!(record.len() < 2_048);
    assert!(!record.windows(32).any(|window| window == [1_u8; 32]));
    assert!(!format!("{:?}", manager(&store, (1, 2_000), calls)?).contains("010101"));
    Ok(())
}

fn duplicate_peer_record() -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(96);
    writer.array(2);
    writer.unsigned(500);
    writer.array(2);
    for _ in 0..2 {
        writer.array(2);
        writer.bytes(&[0x91; 32]);
        writer.array(1);
        writer.unsigned(500);
    }
    writer.finish()
}
