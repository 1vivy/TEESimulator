use std::sync::Arc;

use super::{
    BridgeError,
    deadline::Control,
    executor_state::{Counters, Shared},
};

#[derive(Clone, Copy, Debug)]
pub(super) enum ResourceKind {
    Socket,
    StagedDto,
}

#[derive(Debug)]
pub(super) struct QueuedGuard {
    shared: Arc<Shared>,
    held: bool,
}

impl QueuedGuard {
    pub(super) const fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            held: false,
        }
    }

    pub(super) fn acquire_locked(&mut self, counters: &mut Counters) -> Result<(), BridgeError> {
        let queued = counters
            .queued
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        counters.queued = queued;
        self.held = true;
        Ok(())
    }

    pub(super) fn transition_locked(
        &mut self,
        counters: &mut Counters,
        active: &mut ActiveGuard,
    ) -> Result<(), BridgeError> {
        active.acquire_locked(counters)?;
        self.release_locked(counters);
        Ok(())
    }

    pub(super) const fn is_held(&self) -> bool {
        self.held
    }

    const fn release_locked(&mut self, counters: &mut Counters) {
        if self.held {
            if let Some(queued) = counters.queued.checked_sub(1) {
                counters.queued = queued;
            }
            self.held = false;
        }
    }
}

impl Drop for QueuedGuard {
    fn drop(&mut self) {
        if self.held {
            self.held = false;
            let mut counters = self.shared.lock_for_cleanup();
            if let Some(queued) = counters.queued.checked_sub(1) {
                counters.queued = queued;
            }
            drop(counters);
            self.shared.changed.notify_one();
        }
    }
}

#[derive(Debug)]
pub(super) struct ActiveGuard {
    shared: Arc<Shared>,
    control: Arc<Control>,
    held: bool,
}

impl ActiveGuard {
    pub(super) const fn new(shared: Arc<Shared>, control: Arc<Control>) -> Self {
        Self {
            shared,
            control,
            held: false,
        }
    }

    pub(super) fn acquire_locked(&mut self, counters: &mut Counters) -> Result<(), BridgeError> {
        let active = counters
            .active
            .checked_add(1)
            .ok_or(BridgeError::Capacity)?;
        counters
            .controls
            .try_reserve(1)
            .map_err(|_| BridgeError::Allocation)?;
        counters.active = active;
        self.held = true;
        counters.controls.push(Arc::clone(&self.control));
        Ok(())
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.held {
            self.held = false;
            let mut counters = self.shared.lock_for_cleanup();
            if let Some(active) = counters.active.checked_sub(1) {
                counters.active = active;
            }
            counters
                .controls
                .retain(|control| !Arc::ptr_eq(control, &self.control));
            drop(counters);
            self.shared.changed.notify_one();
        }
    }
}

#[derive(Debug)]
pub(super) struct ResourceGuard {
    shared: Arc<Shared>,
    kind: ResourceKind,
    held: bool,
}

impl ResourceGuard {
    pub(super) fn acquire(shared: Arc<Shared>, kind: ResourceKind) -> Result<Self, BridgeError> {
        let mut guard = Self {
            shared,
            kind,
            held: false,
        };
        {
            let mut counters = guard.shared.lock()?;
            let count = match guard.kind {
                ResourceKind::Socket => &mut counters.sockets,
                ResourceKind::StagedDto => &mut counters.staged_dtos,
            };
            *count = count.checked_add(1).ok_or(BridgeError::Capacity)?;
            guard.held = true;
            drop(counters);
        }
        Ok(guard)
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if self.held {
            let mut counters = self.shared.lock_for_cleanup();
            let count = match self.kind {
                ResourceKind::Socket => &mut counters.sockets,
                ResourceKind::StagedDto => &mut counters.staged_dtos,
            };
            if let Some(remaining) = count.checked_sub(1) {
                *count = remaining;
            }
            self.held = false;
            drop(counters);
        }
    }
}
