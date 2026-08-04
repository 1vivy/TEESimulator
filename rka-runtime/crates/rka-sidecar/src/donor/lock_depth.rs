use std::cell::Cell;

thread_local! {
    static DONOR_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(super) struct DonorLockGuard;

impl DonorLockGuard {
    pub(super) fn enter() -> Self {
        DONOR_LOCK_DEPTH.with(|depth| {
            debug_assert!(depth.get() < usize::MAX);
            depth.set(depth.get().saturating_add(1));
        });
        Self
    }
}

impl Drop for DonorLockGuard {
    fn drop(&mut self) {
        DONOR_LOCK_DEPTH.with(|depth| {
            debug_assert!(depth.get() > 0);
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

/// Returns the current thread's donor lock depth for broker-entry assertions.
#[doc(hidden)]
#[must_use]
pub fn donor_lock_depth() -> usize {
    DONOR_LOCK_DEPTH.get()
}
