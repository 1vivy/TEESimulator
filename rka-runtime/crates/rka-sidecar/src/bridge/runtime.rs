use std::{
    sync::{Arc, Condvar, Mutex, MutexGuard, mpsc},
    thread,
    time::{Duration, Instant},
};

use super::{BridgeError, CancellationToken, cancel::CancellationFlag};

const MAX_ACTIVE: usize = 4;
const MAX_QUEUED: usize = 4;
const DEADLINE: Duration = Duration::from_secs(5);

/// Sidecar topology role with an independent executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SidecarRole {
    /// Sidecar connects to the donor broker server.
    Donor,
    /// Sidecar accepts the candidate broker client.
    Candidate,
}

#[derive(Debug)]
struct Counters {
    active: usize,
    queued: usize,
    live_tasks: usize,
    generation: u64,
    closed: bool,
}

/// Binary-observable executor state used by cleanup checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RuntimeSnapshot {
    /// Currently executing handlers.
    pub active: usize,
    #[doc = "Handlers waiting for an active permit."]
    pub queued: usize,
    #[doc = "Spawned handler tasks not yet joined."]
    pub live_tasks: usize,
    #[doc = "Current reconnect generation."]
    pub generation: u64,
    #[doc = "Whether the executor is closed to new work."]
    pub closed: bool,
}

#[derive(Debug)]
struct Shared {
    counters: Mutex<Counters>,
    changed: Condvar,
}

/// Bounded per-role executor with one aggregate five-second budget.
#[derive(Debug)]
pub struct RoleExecutor {
    role: SidecarRole,
    shared: Arc<Shared>,
}

impl RoleExecutor {
    /// Creates one role-isolated executor.
    pub fn new(role: SidecarRole) -> Self {
        Self {
            role,
            shared: Arc::new(Shared {
                counters: Mutex::new(Counters {
                    active: 0,
                    queued: 0,
                    live_tasks: 0,
                    generation: 0,
                    closed: false,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    #[doc = "Returns the fixed topology role."]
    pub const fn role(&self) -> SidecarRole {
        self.role
    }

    #[doc = "Returns the current reconnect generation."]
    pub fn generation(&self) -> Result<u64, BridgeError> {
        Ok(lock(&self.shared)?.generation)
    }

    #[doc = "Executes within the fixed five-second aggregate budget."]
    pub fn execute<T, F>(&self, operation: F) -> Result<T, BridgeError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> Result<T, BridgeError> + Send + 'static,
    {
        self.execute_with_deadline(DEADLINE, operation)
    }

    #[doc = "Executes within a smaller injected aggregate budget."]
    pub fn execute_with_deadline<T, F>(
        &self,
        budget: Duration,
        operation: F,
    ) -> Result<T, BridgeError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> Result<T, BridgeError> + Send + 'static,
    {
        if budget.is_zero() || budget > DEADLINE {
            return Err(BridgeError::Deadline);
        }
        let started = Instant::now();
        self.acquire(started, budget)?;
        let cancellation = Arc::new(CancellationFlag::new());
        let token = CancellationToken(Arc::clone(&cancellation));
        let shared = Arc::clone(&self.shared);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(match self.role {
                SidecarRole::Donor => "rka-bridge-donor".to_owned(),
                SidecarRole::Candidate => "rka-bridge-candidate".to_owned(),
            })
            .spawn(move || {
                let result = operation(token);
                let _sent = sender.send(result);
                release(&shared);
            })
            .map_err(|_| {
                release(&self.shared);
                BridgeError::Capacity
            })?;
        let remaining = budget
            .checked_sub(started.elapsed())
            .ok_or(BridgeError::Deadline)?;
        let result = match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancellation.cancel();
                Err(BridgeError::Deadline)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BridgeError::PeerDied),
        };
        if result.is_err() {
            cancellation.cancel();
        }
        worker.join().map_err(|_| BridgeError::PeerDied)?;
        result
    }

    #[doc = "Advances the generation after old work is gone."]
    pub fn reconnect(&self) -> Result<u64, BridgeError> {
        let mut counters = lock(&self.shared)?;
        if counters.active != 0 || counters.queued != 0 || counters.live_tasks != 0 {
            return Err(BridgeError::Capacity);
        }
        counters.generation = counters
            .generation
            .checked_add(1)
            .ok_or(BridgeError::Generation)?;
        counters.closed = false;
        Ok(counters.generation)
    }

    #[doc = "Rejects new work and wakes queued callers."]
    pub fn close(&self) -> Result<(), BridgeError> {
        let mut counters = lock(&self.shared)?;
        counters.closed = true;
        drop(counters);
        self.shared.changed.notify_all();
        Ok(())
    }

    #[doc = "Captures cleanup counters without handler material."]
    pub fn snapshot(&self) -> Result<RuntimeSnapshot, BridgeError> {
        let counters = lock(&self.shared)?;
        Ok(RuntimeSnapshot {
            active: counters.active,
            queued: counters.queued,
            live_tasks: counters.live_tasks,
            generation: counters.generation,
            closed: counters.closed,
        })
    }

    fn acquire(&self, started: Instant, budget: Duration) -> Result<(), BridgeError> {
        let mut counters = lock(&self.shared)?;
        if counters.closed {
            return Err(BridgeError::PeerDied);
        }
        if counters.active >= MAX_ACTIVE {
            if counters.queued >= MAX_QUEUED {
                return Err(BridgeError::QueueSaturated);
            }
            counters.queued = counters
                .queued
                .checked_add(1)
                .ok_or(BridgeError::Capacity)?;
            while counters.active >= MAX_ACTIVE && !counters.closed {
                let remaining = budget
                    .checked_sub(started.elapsed())
                    .ok_or(BridgeError::Deadline)?;
                let waited = self
                    .shared
                    .changed
                    .wait_timeout(counters, remaining)
                    .map_err(|_| BridgeError::Io)?;
                counters = waited.0;
                if waited.1.timed_out() {
                    counters.queued = counters.queued.saturating_sub(1);
                    return Err(BridgeError::Deadline);
                }
            }
            counters.queued = counters.queued.saturating_sub(1);
        }
        if counters.closed {
            return Err(BridgeError::PeerDied);
        }
        counters.active = counters
            .active
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        counters.live_tasks = counters
            .live_tasks
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        drop(counters);
        Ok(())
    }
}

fn lock(shared: &Shared) -> Result<MutexGuard<'_, Counters>, BridgeError> {
    shared.counters.lock().map_err(|_| BridgeError::Io)
}

fn release(shared: &Shared) {
    if let Ok(mut counters) = shared.counters.lock() {
        counters.active = counters.active.saturating_sub(1);
        counters.live_tasks = counters.live_tasks.saturating_sub(1);
        shared.changed.notify_one();
    }
}
