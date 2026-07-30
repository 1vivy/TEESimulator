use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[derive(Debug)]
pub(super) struct CancellationFlag(AtomicBool);

impl CancellationFlag {
    pub(super) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub(super) fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[doc = "Cooperative handler cancellation token."]
#[derive(Clone, Debug)]
pub struct CancellationToken(pub(super) Arc<CancellationFlag>);

impl CancellationToken {
    #[doc = "Reports whether deadline, peer, or caller cancelled work."]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled()
    }

    #[doc = "Blocks cooperatively until cancellation is requested."]
    pub fn wait_cancelled(&self) {
        while !self.is_cancelled() {
            thread::park_timeout(Duration::from_millis(1));
        }
    }
}
