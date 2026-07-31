#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(
    clippy::unwrap_used,
    reason = "fixture construction must fail immediately"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use rka_state::{
    AmbiguousMaterial, CrashRecovery, MutationCrashState, QuarantineAction, QuarantineActions,
    QuarantineLedger, QuarantineReason, StateError, StateStore,
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
}

impl QuarantineActions for Actions {
    fn cancel(&mut self) {
        self.cancels = self.cancels.saturating_add(1);
    }

    fn apply(&mut self, handle: [u8; 32], action: QuarantineAction) {
        self.events.push((handle, action));
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
    assert!(
        ledger
            .recover_crash(
                CrashRecovery::new(MutationCrashState::RkpKeyGenerating, &material),
                &mut actions,
            )
            .is_err()
    );
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
