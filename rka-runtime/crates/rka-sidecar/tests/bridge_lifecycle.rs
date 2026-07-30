//! Capacity lifecycle regression tests.

use std::{
    error::Error,
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use rka_sidecar::bridge::{
    BridgeError, BridgeMessage, BrokerOperation, Hash32, RequestId, RoleExecutor, SidecarRole,
};

struct SocketPath(PathBuf);

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

const fn response() -> BridgeMessage {
    BridgeMessage::Error(RequestId::new(1), 1, Hash32::new([0; 32]))
}

type Worker = JoinHandle<Result<BridgeMessage, BridgeError>>;

struct Blocked {
    paths: Vec<SocketPath>,
    workers: Vec<Worker>,
}

fn spawn_blocked(
    executor: &Arc<RoleExecutor>,
    name: &str,
    count: usize,
) -> Result<Blocked, Box<dyn Error>> {
    let response = Arc::new(response());
    let mut paths = Vec::new();
    let mut workers = Vec::new();
    for index in 0..count {
        let path = SocketPath(std::env::temp_dir().join(format!(
            "rka-task8-lifecycle-{name}-{index}-{}",
            std::process::id()
        )));
        let listener = UnixListener::bind(&path.0)?;
        let owned_executor = Arc::clone(executor);
        let owned_response = Arc::clone(&response);
        workers.push(thread::spawn(move || {
            owned_executor.dispatch(BrokerOperation::Candidate {
                listener: &listener,
                response: &owned_response,
            })
        }));
        paths.push(path);
    }
    Ok(Blocked { paths, workers })
}

fn wait_for(executor: &RoleExecutor, active: usize, queued: usize) -> Result<(), Box<dyn Error>> {
    for _ in 0..100_000 {
        let snapshot = executor.snapshot()?;
        if snapshot.active == active && snapshot.queued == queued {
            return Ok(());
        }
        thread::yield_now();
    }
    Err("executor state did not converge".into())
}

fn assert_empty(executor: &RoleExecutor) -> Result<(), Box<dyn Error>> {
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
fn bridge_expired_queued_operation_releases_capacity_before_reconnect() -> Result<(), Box<dyn Error>>
{
    let executor = Arc::new(RoleExecutor::new(SidecarRole::Candidate));
    let response = Arc::new(response());
    let blocked = spawn_blocked(&executor, "regression", 4)?;
    wait_for(&executor, 4, 0)?;

    let queued_path = SocketPath(
        std::env::temp_dir().join(format!("rka-task8-expired-fifth-{}", std::process::id())),
    );
    let queued_listener = UnixListener::bind(&queued_path.0)?;
    assert_eq!(
        executor.dispatch_with_budget(
            BrokerOperation::Candidate {
                listener: &queued_listener,
                response: &response,
            },
            Duration::from_nanos(1),
        ),
        Err(BridgeError::Deadline)
    );

    executor.close()?;
    executor.close()?;
    for worker in blocked.workers {
        assert!(worker.join().is_ok_and(|result| result.is_err()));
    }
    assert_empty(&executor)?;
    assert_eq!(executor.reconnect()?, 1);

    let next_path = SocketPath(
        std::env::temp_dir().join(format!("rka-task8-after-reconnect-{}", std::process::id())),
    );
    let next_listener = UnixListener::bind(&next_path.0)?;
    assert_eq!(
        executor.dispatch_with_budget(
            BrokerOperation::Candidate {
                listener: &next_listener,
                response: &response,
            },
            Duration::from_millis(1),
        ),
        Err(BridgeError::Deadline)
    );
    assert_empty(&executor)
}

#[test]
fn bridge_queued_guard_transitions_once_to_active_guard() -> Result<(), Box<dyn Error>> {
    let executor = Arc::new(RoleExecutor::new(SidecarRole::Candidate));
    let blocked = spawn_blocked(&executor, "transition", 5)?;
    wait_for(&executor, 4, 1)?;

    let clients = blocked
        .paths
        .iter()
        .map(|path| UnixStream::connect(&path.0))
        .collect::<Result<Vec<_>, _>>()?;
    for worker in blocked.workers {
        assert!(worker.join().is_ok_and(|result| result.is_err()));
    }
    drop(clients);
    assert_empty(&executor)?;
    assert_eq!(executor.reconnect()?, 1);
    Ok(())
}

#[test]
fn bridge_capacity_guards_survive_concurrent_deadline_and_repeated_close_stress()
-> Result<(), Box<dyn Error>> {
    for round in 0..8 {
        let executor = Arc::new(RoleExecutor::new(SidecarRole::Candidate));
        let response = Arc::new(response());
        let blocked = spawn_blocked(&executor, &format!("stress-{round}"), 4)?;
        wait_for(&executor, 4, 0)?;

        for attempt in 0..8 {
            let path = SocketPath(std::env::temp_dir().join(format!(
                "rka-task8-stress-fifth-{round}-{attempt}-{}",
                std::process::id()
            )));
            let listener = UnixListener::bind(&path.0)?;
            assert_eq!(
                executor.dispatch_with_budget(
                    BrokerOperation::Candidate {
                        listener: &listener,
                        response: &response,
                    },
                    Duration::from_nanos(1),
                ),
                Err(BridgeError::Deadline)
            );
            wait_for(&executor, 4, 0)?;
        }

        let timeout_path = SocketPath(std::env::temp_dir().join(format!(
            "rka-task8-stress-timeout-{round}-{}",
            std::process::id()
        )));
        let timeout_listener = UnixListener::bind(&timeout_path.0)?;
        assert_eq!(
            executor.dispatch_with_budget(
                BrokerOperation::Candidate {
                    listener: &timeout_listener,
                    response: &response,
                },
                Duration::from_millis(2),
            ),
            Err(BridgeError::Deadline)
        );
        wait_for(&executor, 4, 0)?;

        executor.close()?;
        executor.close()?;
        for worker in blocked.workers {
            assert!(worker.join().is_ok_and(|result| result.is_err()));
        }
        assert_empty(&executor)?;
        assert_eq!(executor.reconnect()?, 1);
    }
    Ok(())
}
