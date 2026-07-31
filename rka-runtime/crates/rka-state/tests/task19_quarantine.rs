#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(
    clippy::unwrap_used,
    reason = "fixture construction must fail immediately"
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rka_state::{
    AmbiguousMaterial, CleanupIntent, CrashRecovery, MutationCrashState, QuarantineAction,
    QuarantineActions, QuarantineLedger, QuarantineReason, StateError, StateStore,
};

#[derive(Default)]
struct MemoryStore(RefCell<BTreeMap<Vec<u8>, Vec<u8>>>);

impl StateStore for MemoryStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .0
            .borrow()
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Storage)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.0.borrow_mut().insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

#[derive(Default)]
struct Actions {
    events: Vec<([u8; 32], QuarantineAction)>,
    cancels: usize,
    receipts: BTreeSet<[u8; 32]>,
}

impl QuarantineActions for Actions {
    fn execute(&mut self, intent: CleanupIntent) -> bool {
        if !self.receipts.insert(*intent.action_id()) {
            return true;
        }
        match (intent.handle(), intent.action()) {
            (None, None) => self.cancels = self.cancels.saturating_add(1),
            (Some(handle), Some(action)) => self.events.push((*handle, action)),
            _ => return false,
        }
        true
    }
}

#[test]
fn generating_crash_is_durably_quarantined_once_and_never_replayed() {
    let store = MemoryStore::default();
    let mut ledger = QuarantineLedger::new(&store);
    let material = AmbiguousMaterial::new([1; 16], [2; 16], vec![[3; 32], [4; 32]]).unwrap();
    let mut actions = Actions::default();

    ledger
        .recover_crash(
            CrashRecovery::new(MutationCrashState::RkpKeyGenerating, &material),
            &mut actions,
        )
        .unwrap();

    assert_eq!(actions.cancels, 1);
    assert_eq!(actions.events.len(), 4);
    assert!(!ledger.activation_allowed(&material).unwrap());
    assert_eq!(
        ledger.reason().unwrap(),
        Some(QuarantineReason::GeneratingCrash)
    );
    ledger
        .recover_crash(
            CrashRecovery::new(MutationCrashState::RkpKeyGenerating, &material),
            &mut actions,
        )
        .unwrap();
    assert_eq!(actions.cancels, 1);
    assert_eq!(actions.events.len(), 4);
}

#[test]
fn restart_in_every_mutating_state_retains_quarantine() {
    for state in [
        MutationCrashState::RkpKeyGenerating,
        MutationCrashState::CsrPosting,
        MutationCrashState::PostAmbiguous,
        MutationCrashState::AppKeyGenerating,
    ] {
        let store = MemoryStore::default();
        let mut ledger = QuarantineLedger::new(&store);
        let material = AmbiguousMaterial::new([8; 16], [9; 16], vec![[10; 32]]).unwrap();
        let mut actions = Actions::default();
        ledger
            .recover_crash(CrashRecovery::new(state, &material), &mut actions)
            .unwrap();
        let restarted = QuarantineLedger::new(&store);
        assert!(!restarted.activation_allowed(&material).unwrap());
    }
}

#[test]
fn cleanup_resumes_after_every_persisted_step_boundary() {
    for fail_at in 0..5 {
        let store = MemoryStore::default();
        let material =
            AmbiguousMaterial::new([21; 16], [22; 16], vec![[23; 32], [24; 32]]).unwrap();
        let mut first = FailingActions {
            fail_at,
            calls: 0,
            completed: Vec::new(),
        };
        assert!(
            QuarantineLedger::new(&store)
                .recover_crash(
                    CrashRecovery::new(MutationCrashState::PostAmbiguous, &material),
                    &mut first,
                )
                .is_err()
        );
        assert_eq!(first.completed.len(), fail_at);
        let mut resumed = Actions::default();
        QuarantineLedger::new(&store)
            .recover_crash(
                CrashRecovery::new(MutationCrashState::PostAmbiguous, &material),
                &mut resumed,
            )
            .unwrap();
        assert_eq!(
            resumed.cancels.saturating_add(resumed.events.len()),
            5 - fail_at
        );
    }
}

#[test]
fn crash_after_receiver_effect_before_caller_cursor_never_repeats_effect() {
    let store = FailCursorStore::default();
    let material = AmbiguousMaterial::new([31; 16], [32; 16], vec![[33; 32]]).unwrap();
    let mut actions = Actions::default();

    assert!(
        QuarantineLedger::new(&store)
            .recover_crash(
                CrashRecovery::new(MutationCrashState::PostAmbiguous, &material),
                &mut actions,
            )
            .is_err()
    );
    store.fail.set(false);
    QuarantineLedger::new(&store)
        .recover_crash(
            CrashRecovery::new(MutationCrashState::PostAmbiguous, &material),
            &mut actions,
        )
        .unwrap();

    assert_eq!(actions.cancels, 1);
}

#[derive(Default)]
struct FailCursorStore {
    values: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
    writes: RefCell<usize>,
    fail: std::cell::Cell<bool>,
}

impl StateStore for FailCursorStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .values
            .borrow()
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Storage)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let next = self.writes.borrow().saturating_add(1);
        *self.writes.borrow_mut() = next;
        if next == 2 && !self.fail.replace(true) {
            return Err(StateError::Storage);
        }
        self.values
            .borrow_mut()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

struct FailingActions {
    fail_at: usize,
    calls: usize,
    completed: Vec<usize>,
}

impl QuarantineActions for FailingActions {
    fn execute(&mut self, _intent: CleanupIntent) -> bool {
        self.step()
    }
}

impl FailingActions {
    fn step(&mut self) -> bool {
        let current = self.calls;
        self.calls = self.calls.saturating_add(1);
        if current == self.fail_at {
            false
        } else {
            self.completed.push(current);
            true
        }
    }
}
