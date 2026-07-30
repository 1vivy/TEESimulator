//! Real `AF_UNIX` credentials and bounded role executor tests.

use std::{
    error::Error,
    os::unix::net::UnixStream,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use rka_sidecar::bridge::{
    BridgeError, PeerCredentials, RoleExecutor, RuntimeSnapshot, SidecarRole,
};

fn unlocked_snapshot(executor: &RoleExecutor) -> Result<RuntimeSnapshot, BridgeError> {
    executor.snapshot()
}

#[test]
fn bridge_peer_credentials_come_from_real_unix_socket() -> Result<(), Box<dyn Error>> {
    let (left, _right) = UnixStream::pair()?;
    let credentials = PeerCredentials::from_stream(&left)?;
    assert_eq!(credentials.pid, i32::try_from(std::process::id())?);
    assert_eq!(credentials.uid, rustix::process::getuid().as_raw());
    assert_eq!(credentials.gid, rustix::process::getgid().as_raw());
    Ok(())
}

#[test]
fn bridge_deadline_cancels_handler_and_cleans_every_counter() -> Result<(), Box<dyn Error>> {
    let executor = RoleExecutor::new(SidecarRole::Donor);
    let result = executor.execute_with_deadline(Duration::from_millis(20), |token| {
        token.wait_cancelled();
        Err::<(), BridgeError>(BridgeError::Cancelled)
    });
    assert_eq!(result, Err(BridgeError::Deadline));
    let snapshot = unlocked_snapshot(&executor)?;
    assert_eq!(
        (
            snapshot.active,
            snapshot.queued,
            snapshot.live_tasks,
            snapshot.generation,
            snapshot.closed,
        ),
        (0, 0, 0, 0, false)
    );
    Ok(())
}

#[test]
fn bridge_role_executors_do_not_cross_route_or_starve() -> Result<(), Box<dyn Error>> {
    let donor = RoleExecutor::new(SidecarRole::Donor);
    let candidate = RoleExecutor::new(SidecarRole::Candidate);
    assert_eq!(donor.execute(|_| Ok(11_u8))?, 11);
    assert_eq!(candidate.execute(|_| Ok(22_u8))?, 22);
    assert_eq!(donor.role(), SidecarRole::Donor);
    assert_eq!(candidate.role(), SidecarRole::Candidate);
    Ok(())
}

#[test]
fn bridge_fifth_request_queues_behind_four_active_handlers() -> Result<(), Box<dyn Error>> {
    let executor = Arc::new(RoleExecutor::new(SidecarRole::Candidate));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let mut workers = Vec::new();
    for _ in 0..5 {
        let owned_executor = Arc::clone(&executor);
        let owned_gate = Arc::clone(&gate);
        workers.push(thread::spawn(move || {
            owned_executor.execute(move |_| {
                let (lock, changed) = &*owned_gate;
                let mut released = lock.lock().map_err(|_| BridgeError::Io)?;
                while !*released {
                    released = changed.wait(released).map_err(|_| BridgeError::Io)?;
                }
                drop(released);
                Ok(())
            })
        }));
    }
    for _ in 0..10_000 {
        let snapshot = executor.snapshot()?;
        if snapshot.active == 4 && snapshot.queued == 1 {
            break;
        }
        thread::yield_now();
    }
    let snapshot = executor.snapshot()?;
    assert_eq!((snapshot.active, snapshot.queued), (4, 1));
    let (lock, changed) = &*gate;
    *lock.lock().map_err(|_| BridgeError::Io)? = true;
    changed.notify_all();
    for worker in workers {
        assert!(worker.join().is_ok_and(|result| result.is_ok()));
    }
    assert_eq!(executor.snapshot()?.live_tasks, 0);
    Ok(())
}

#[test]
fn bridge_reconnect_rejects_old_generation_and_clears_closed_state() -> Result<(), Box<dyn Error>> {
    let executor = RoleExecutor::new(SidecarRole::Donor);
    executor.close()?;
    assert_eq!(executor.execute(|_| Ok(())), Err(BridgeError::PeerDied));
    assert_eq!(executor.reconnect()?, 1);
    assert_eq!(executor.execute(|_| Ok(7_u8))?, 7);
    assert_eq!(executor.snapshot()?.generation, 1);
    Ok(())
}
