use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use super::{
    BridgeError, BridgeMessage,
    deadline::{Control, Deadline},
    lifecycle::{ActiveGuard, QueuedGuard, ResourceGuard, ResourceKind},
};

// These limits are donor-wide because every executor shares this state.
const MAX_ACTIVE: usize = 4;
const MAX_QUEUED: usize = 4;

#[derive(Debug)]
pub(super) struct Counters {
    pub(super) active: usize,
    pub(super) queued: usize,
    pub(super) generation: u64,
    pub(super) closed: bool,
    pub(super) sockets: usize,
    pub(super) staged_dtos: usize,
    pub(super) controls: Vec<Arc<Control>>,
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
    pub(super) changed: Condvar,
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
        deadline.remaining()?;
        let mut active = ActiveGuard::new(Arc::clone(self), Arc::clone(&control));
        let mut queued = QueuedGuard::new(Arc::clone(self));
        let mut counters = self.lock()?;
        if counters.active >= MAX_ACTIVE {
            if counters.queued >= MAX_QUEUED {
                return Err(BridgeError::QueueSaturated);
            }
            deadline.remaining()?;
            queued.acquire_locked(&mut counters)?;
            while counters.active >= MAX_ACTIVE && !counters.closed {
                let remaining = deadline.remaining()?;
                let waited = self
                    .changed
                    .wait_timeout(counters, remaining)
                    .map_err(|_| BridgeError::Io)?;
                counters = waited.0;
                if waited.1.timed_out() {
                    deadline.control().expire();
                    return Err(BridgeError::Deadline);
                }
            }
        }
        if counters.closed {
            return Err(BridgeError::PeerDied);
        }
        if counters.active >= MAX_ACTIVE {
            return Err(BridgeError::Capacity);
        }
        if queued.is_held() {
            queued.transition_locked(&mut counters, &mut active)?;
        } else {
            active.acquire_locked(&mut counters)?;
        }
        let generation = counters.generation;
        drop(counters);
        Ok(Permit {
            shared: Arc::clone(self),
            control,
            generation,
            active: Some(active),
            socket: None,
            staged: None,
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

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, Counters>, BridgeError> {
        self.counters.lock().map_err(|_| BridgeError::Io)
    }

    pub(super) fn lock_for_cleanup(&self) -> MutexGuard<'_, Counters> {
        match self.counters.lock() {
            Ok(counters) => counters,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Permit {
    shared: Arc<Shared>,
    control: Arc<Control>,
    pub(super) generation: u64,
    active: Option<ActiveGuard>,
    socket: Option<ResourceGuard>,
    staged: Option<ResourceGuard>,
}

impl Permit {
    pub(super) fn attach(&mut self, stream: &UnixStream) -> Result<(), BridgeError> {
        self.control.attach(stream)?;
        let socket = ResourceGuard::acquire(Arc::clone(&self.shared), ResourceKind::Socket)?;
        self.socket = Some(socket);
        Ok(())
    }

    pub(super) fn stage(&mut self) -> Result<(), BridgeError> {
        let staged = ResourceGuard::acquire(Arc::clone(&self.shared), ResourceKind::StagedDto)?;
        self.staged = Some(staged);
        Ok(())
    }

    pub(super) fn expose(mut self, message: BridgeMessage) -> BridgeMessage {
        drop(self.staged.take());
        message
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.control.detach();
        drop(self.staged.take());
        drop(self.socket.take());
        drop(self.active.take());
    }
}
