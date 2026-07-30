use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use super::{
    BridgeError, BridgeMessage,
    deadline::{Control, Deadline},
};

const MAX_ACTIVE: usize = 4;
const MAX_QUEUED: usize = 4;

#[derive(Debug)]
struct Counters {
    active: usize,
    queued: usize,
    generation: u64,
    closed: bool,
    sockets: usize,
    staged_dtos: usize,
    controls: Vec<Arc<Control>>,
}

/// Binary-observable executor state used by cleanup checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RuntimeSnapshot {
    /// Currently executing closed operations.
    pub active: usize,
    /// Operations waiting for an active permit.
    pub queued: usize,
    /// Runtime-owned worker threads; always zero.
    pub live_tasks: usize,
    /// Current reconnect generation.
    pub generation: u64,
    /// Whether the executor rejects new work.
    pub closed: bool,
    /// Runtime-owned connected sockets.
    pub sockets: usize,
    /// Decoded DTOs not yet exposed or wiped.
    pub staged_dtos: usize,
    /// Borrowed public handles; always zero.
    pub borrowed_handles: usize,
}

#[derive(Debug)]
pub(super) struct Shared {
    counters: Mutex<Counters>,
    changed: Condvar,
}

impl Shared {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: Mutex::new(Counters {
                active: 0,
                queued: 0,
                generation: 0,
                closed: false,
                sockets: 0,
                staged_dtos: 0,
                controls: Vec::new(),
            }),
            changed: Condvar::new(),
        })
    }

    pub(super) fn acquire(
        self: &Arc<Self>,
        deadline: &Deadline,
        control: Arc<Control>,
    ) -> Result<Permit, BridgeError> {
        let mut counters = self.lock()?;
        if counters.active >= MAX_ACTIVE {
            if counters.queued >= MAX_QUEUED {
                return Err(BridgeError::QueueSaturated);
            }
            counters.queued = counters
                .queued
                .checked_add(1)
                .ok_or(BridgeError::Capacity)?;
            while counters.active >= MAX_ACTIVE && !counters.closed {
                let waited = self
                    .changed
                    .wait_timeout(counters, deadline.remaining()?)
                    .map_err(|_| BridgeError::Io)?;
                counters = waited.0;
                if waited.1.timed_out() {
                    counters.queued = counters.queued.saturating_sub(1);
                    deadline.control().expire();
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
        let generation = counters.generation;
        counters.controls.push(Arc::clone(&control));
        drop(counters);
        Ok(Permit {
            shared: Arc::clone(self),
            control,
            generation,
            socket_attached: false,
            staged: false,
        })
    }

    pub(super) fn reconnect(&self) -> Result<u64, BridgeError> {
        let mut counters = self.lock()?;
        if counters.active != 0 || counters.queued != 0 || !counters.controls.is_empty() {
            return Err(BridgeError::Capacity);
        }
        counters.generation = counters
            .generation
            .checked_add(1)
            .ok_or(BridgeError::Generation)?;
        counters.closed = false;
        Ok(counters.generation)
    }

    pub(super) fn close(&self) -> Result<(), BridgeError> {
        let mut counters = self.lock()?;
        counters.closed = true;
        let controls = counters.controls.clone();
        drop(counters);
        for control in controls {
            control.close();
        }
        self.changed.notify_all();
        Ok(())
    }

    pub(super) fn snapshot(&self) -> Result<RuntimeSnapshot, BridgeError> {
        let counters = self.lock()?;
        Ok(RuntimeSnapshot {
            active: counters.active,
            queued: counters.queued,
            live_tasks: 0,
            generation: counters.generation,
            closed: counters.closed,
            sockets: counters.sockets,
            staged_dtos: counters.staged_dtos,
            borrowed_handles: 0,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Counters>, BridgeError> {
        self.counters.lock().map_err(|_| BridgeError::Io)
    }
}

#[derive(Debug)]
pub(super) struct Permit {
    shared: Arc<Shared>,
    control: Arc<Control>,
    pub(super) generation: u64,
    socket_attached: bool,
    staged: bool,
}

impl Permit {
    pub(super) fn attach(&mut self, stream: &UnixStream) -> Result<(), BridgeError> {
        self.control.attach(stream)?;
        let mut counters = self.shared.lock()?;
        counters.sockets = counters
            .sockets
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        drop(counters);
        self.socket_attached = true;
        Ok(())
    }

    pub(super) fn stage(&mut self) -> Result<(), BridgeError> {
        let mut counters = self.shared.lock()?;
        counters.staged_dtos = counters
            .staged_dtos
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        drop(counters);
        self.staged = true;
        Ok(())
    }

    pub(super) fn expose(mut self, message: BridgeMessage) -> Result<BridgeMessage, BridgeError> {
        if self.staged {
            let mut counters = self.shared.lock()?;
            counters.staged_dtos = counters.staged_dtos.saturating_sub(1);
            drop(counters);
            self.staged = false;
        }
        Ok(message)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.control.detach();
        if let Ok(mut counters) = self.shared.counters.lock() {
            counters.active = counters.active.saturating_sub(1);
            counters.sockets = counters
                .sockets
                .saturating_sub(usize::from(self.socket_attached));
            counters.staged_dtos = counters
                .staged_dtos
                .saturating_sub(usize::from(self.staged));
            counters
                .controls
                .retain(|control| !Arc::ptr_eq(control, &self.control));
            self.shared.changed.notify_one();
        }
    }
}
