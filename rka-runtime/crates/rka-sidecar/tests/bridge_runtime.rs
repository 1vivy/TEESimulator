//! Real credentials and closed bounded role executor tests.

use std::{
    error::Error,
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use rka_sidecar::bridge::{
    BridgeError, BridgeMessage, BrokerOperation, Hash32, PeerCredentials, PublicBytes, RequestId,
    RoleExecutor, SidecarRole,
};

struct SocketPath(PathBuf);

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

fn path(name: &str) -> SocketPath {
    SocketPath(
        std::env::temp_dir().join(format!("rka-task8-runtime-{name}-{}", std::process::id())),
    )
}

const fn response() -> BridgeMessage {
    BridgeMessage::Error(RequestId::new(1), 1, Hash32::new([0; 32]))
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
fn bridge_blocked_closed_operation_returns_and_cleans_every_counter() -> Result<(), Box<dyn Error>>
{
    let socket_path = path("deadline");
    let listener = UnixListener::bind(&socket_path.0)?;
    let response = response();
    let executor = RoleExecutor::new(SidecarRole::Candidate);
    let started = Instant::now();
    let result = executor.dispatch_with_budget(
        BrokerOperation::Candidate {
            listener: &listener,
            response: &response,
        },
        Duration::from_millis(20),
    );
    assert_eq!(result, Err(BridgeError::Deadline));
    assert!(started.elapsed() < Duration::from_secs(1));
    let snapshot = executor.snapshot()?;
    assert_eq!(
        (
            snapshot.active,
            snapshot.queued,
            snapshot.live_tasks,
            snapshot.sockets,
            snapshot.staged_dtos,
            snapshot.borrowed_handles,
        ),
        (0, 0, 0, 0, 0, 0)
    );
    Ok(())
}

#[test]
fn bridge_role_executors_reject_cross_routing_without_handler_api() -> Result<(), Box<dyn Error>> {
    let socket_path = path("roles");
    let listener = UnixListener::bind(&socket_path.0)?;
    let response = response();
    let donor = RoleExecutor::new(SidecarRole::Donor);
    let candidate = RoleExecutor::new(SidecarRole::Candidate);
    assert_eq!(
        donor.dispatch_with_budget(
            BrokerOperation::Candidate {
                listener: &listener,
                response: &response,
            },
            Duration::from_millis(20),
        ),
        Err(BridgeError::WrongRole)
    );
    let request = BridgeMessage::PublicKeyRequest(
        RequestId::new(1),
        PublicBytes::bounded(&[0; 16], 16, 64)?,
        1,
    );
    assert_eq!(
        candidate.dispatch_with_budget(
            BrokerOperation::Donor {
                socket_path: &socket_path.0,
                request: &request,
            },
            Duration::from_millis(20),
        ),
        Err(BridgeError::WrongRole)
    );
    Ok(())
}

#[test]
fn bridge_fifth_closed_operation_queues_then_close_wakes_all() -> Result<(), Box<dyn Error>> {
    let executor = Arc::new(RoleExecutor::new(SidecarRole::Candidate));
    let response = Arc::new(response());
    let mut paths = Vec::new();
    let mut listeners = Vec::new();
    for index in 0..5 {
        let socket_path = path(&format!("queue-{index}"));
        listeners.push(UnixListener::bind(&socket_path.0)?);
        paths.push(socket_path);
    }
    let workers = listeners
        .into_iter()
        .map(|listener| {
            let owned_executor = Arc::clone(&executor);
            let owned_response = Arc::clone(&response);
            thread::spawn(move || {
                owned_executor.dispatch(BrokerOperation::Candidate {
                    listener: &listener,
                    response: &owned_response,
                })
            })
        })
        .collect::<Vec<_>>();
    for _ in 0..10_000 {
        let snapshot = executor.snapshot()?;
        if snapshot.active == 4 && snapshot.queued == 1 {
            break;
        }
        thread::yield_now();
    }
    assert_eq!(
        (executor.snapshot()?.active, executor.snapshot()?.queued),
        (4, 1)
    );
    executor.close()?;
    for worker in workers {
        assert!(worker.join().is_ok_and(|result| result.is_err()));
    }
    let snapshot = executor.snapshot()?;
    assert_eq!(
        (snapshot.active, snapshot.queued, snapshot.sockets),
        (0, 0, 0)
    );
    drop(paths);
    Ok(())
}

#[test]
fn bridge_reconnect_rejects_live_generation_then_clears_closed_state() -> Result<(), Box<dyn Error>>
{
    let executor = RoleExecutor::new(SidecarRole::Donor);
    executor.close()?;
    assert_eq!(executor.reconnect()?, 1);
    assert_eq!(executor.snapshot()?.generation, 1);
    assert!(!executor.snapshot()?.closed);
    Ok(())
}
