use std::{
    os::unix::net::UnixStream,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    time::Duration,
};

use super::{
    BridgeError, BridgeMessage, ExchangeRole, Hash32, RequestId,
    deadline::{Control, Deadline},
    encode_frame,
    executor_state::Shared,
    socket::{read_message, write_message},
};

fn acquire(shared: &Arc<Shared>) -> Result<super::executor_state::Permit, BridgeError> {
    let control = Control::new()?;
    let deadline = Deadline::new(Duration::from_secs(1), Arc::clone(&control))?;
    shared.acquire(&deadline, control)
}

fn active_read_error(shared: &Arc<Shared>) -> Result<(), BridgeError> {
    let control = Control::new()?;
    let deadline = Deadline::new(Duration::from_secs(1), Arc::clone(&control))?;
    let mut permit = shared.acquire(&deadline, control)?;
    let (stream, peer) = UnixStream::pair().map_err(|_| BridgeError::Io)?;
    permit.attach(&stream)?;
    drop(peer);
    let _message = read_message(&stream, ExchangeRole::CandidateRequest, &deadline)?;
    Ok(())
}

fn active_write_error(shared: &Arc<Shared>) -> Result<(), BridgeError> {
    let control = Control::new()?;
    let deadline = Deadline::new(Duration::from_secs(1), Arc::clone(&control))?;
    let mut permit = shared.acquire(&deadline, control)?;
    let (stream, peer) = UnixStream::pair().map_err(|_| BridgeError::Io)?;
    permit.attach(&stream)?;
    drop(peer);
    let message = BridgeMessage::Error(RequestId::new(8), 1, Hash32::new([0; 32]));
    let frame = encode_frame(&message, ExchangeRole::CandidateResponse)?;
    write_message(&stream, &frame, &deadline)
}

fn assert_empty(shared: &Shared) {
    let snapshot = shared.snapshot();
    assert!(snapshot.is_ok_and(|state| {
        state.active == 0 && state.queued == 0 && state.sockets == 0 && state.staged_dtos == 0
    }));
}

fn assert_counts(shared: &Shared, expected: (usize, usize, usize)) {
    let snapshot = shared.snapshot();
    assert!(
        snapshot
            .is_ok_and(|state| { (state.active, state.sockets, state.staged_dtos) == expected })
    );
}

#[test]
fn bridge_resource_guards_release_pre_auth_staged_error_and_success_paths() {
    let shared = Shared::new();

    let before = Deadline::new(
        Duration::ZERO,
        Control::new().unwrap_or_else(|error| {
            panic!("control setup failed: {error}");
        }),
    );
    assert!(matches!(before, Err(BridgeError::Deadline)));
    assert_empty(&shared);

    let immediate = acquire(&shared);
    assert!(immediate.is_ok());
    assert_counts(&shared, (1, 0, 0));
    drop(immediate);
    assert_empty(&shared);

    let (stream, _peer) = UnixStream::pair().unwrap_or_else(|error| {
        panic!("socket pair failed: {error}");
    });
    let mut attached = acquire(&shared).unwrap_or_else(|error| {
        panic!("permit acquisition failed: {error}");
    });
    assert!(attached.attach(&stream).is_ok());
    assert_counts(&shared, (1, 1, 0));
    drop(attached);
    assert_empty(&shared);

    for error in [
        BridgeError::Deadline,
        BridgeError::PeerDied,
        BridgeError::PeerIdentity,
        BridgeError::Io,
        BridgeError::Correlation,
    ] {
        let mut staged = acquire(&shared).unwrap_or_else(|failure| {
            panic!("permit acquisition failed: {failure}");
        });
        assert!(staged.attach(&stream).is_ok());
        assert!(staged.stage().is_ok());
        assert_counts(&shared, (1, 1, 1));
        let result: Result<(), BridgeError> = Err(error);
        drop(staged);
        assert_eq!(result, Err(error));
        assert_empty(&shared);
    }

    let mut success = acquire(&shared).unwrap_or_else(|error| {
        panic!("permit acquisition failed: {error}");
    });
    assert!(success.attach(&stream).is_ok());
    assert!(success.stage().is_ok());
    assert_counts(&shared, (1, 1, 1));
    let message = BridgeMessage::Error(RequestId::new(7), 1, Hash32::new([0; 32]));
    assert_eq!(success.expose(message).request_id(), RequestId::new(7));
    assert_empty(&shared);
}

#[test]
fn bridge_resource_guards_release_when_panic_is_caught() {
    let shared = Shared::new();
    let owned = Arc::clone(&shared);
    let unwind = catch_unwind(AssertUnwindSafe(move || {
        let (stream, _peer) = UnixStream::pair().unwrap_or_else(|error| {
            panic!("socket pair failed: {error}");
        });
        let mut permit = acquire(&owned).unwrap_or_else(|error| {
            panic!("permit acquisition failed: {error}");
        });
        assert!(permit.attach(&stream).is_ok());
        assert!(permit.stage().is_ok());
        panic!("forced lifecycle unwind");
    }));
    assert!(unwind.is_err());
    assert_empty(&shared);
}

#[test]
fn bridge_active_read_and_write_errors_release_guards() {
    let shared = Shared::new();
    assert_eq!(active_read_error(&shared), Err(BridgeError::PeerDied));
    assert_empty(&shared);
    assert_eq!(active_write_error(&shared), Err(BridgeError::PeerDied));
    assert_empty(&shared);
}
