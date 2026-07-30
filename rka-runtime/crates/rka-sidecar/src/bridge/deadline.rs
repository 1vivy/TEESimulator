use std::{
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use rustix::{
    event::{EventfdFlags, PollFd, PollFlags, Timespec, eventfd, poll},
    fd::OwnedFd,
    io::{read, write},
    net::{Shutdown, shutdown},
};

use super::BridgeError;

const RUNNING: u8 = 0;
const EXPIRED: u8 = 1;
const CLOSED: u8 = 2;
const MAX_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Control {
    event: OwnedFd,
    state: AtomicU8,
    socket: Mutex<Option<UnixStream>>,
}

impl Control {
    pub(super) fn new() -> Result<Arc<Self>, BridgeError> {
        let event = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
            .map_err(|_| BridgeError::Io)?;
        Ok(Arc::new(Self {
            event,
            state: AtomicU8::new(RUNNING),
            socket: Mutex::new(None),
        }))
    }

    pub(super) fn attach(&self, stream: &UnixStream) -> Result<(), BridgeError> {
        let clone = stream.try_clone().map_err(|_| BridgeError::Io)?;
        *self.socket.lock().map_err(|_| BridgeError::Io)? = Some(clone);
        Ok(())
    }

    pub(super) fn detach(&self) {
        if let Ok(mut socket) = self.socket.lock() {
            *socket = None;
        }
    }

    pub(super) fn expire(&self) {
        self.signal(EXPIRED);
    }

    pub(super) fn close(&self) {
        self.signal(CLOSED);
    }

    fn signal(&self, state: u8) {
        self.state.store(state, Ordering::Release);
        if let Ok(socket) = self.socket.lock()
            && let Some(stream) = socket.as_ref()
        {
            let _shutdown = shutdown(stream, Shutdown::Both);
        }
        let _written = write(&self.event, &1_u64.to_ne_bytes());
    }

    fn error(&self) -> BridgeError {
        match self.state.load(Ordering::Acquire) {
            EXPIRED => BridgeError::Deadline,
            CLOSED => BridgeError::PeerDied,
            _ => BridgeError::Cancelled,
        }
    }

    fn drain(&self) {
        let mut value = [0_u8; 8];
        let _drained = read(&self.event, &mut value);
    }
}

#[derive(Debug)]
pub(super) struct Deadline {
    expires: Instant,
    control: Arc<Control>,
}

impl Deadline {
    pub(super) fn new(budget: Duration, control: Arc<Control>) -> Result<Self, BridgeError> {
        if budget.is_zero() || budget > MAX_BUDGET {
            return Err(BridgeError::Deadline);
        }
        let expires = Instant::now()
            .checked_add(budget)
            .ok_or(BridgeError::Deadline)?;
        Ok(Self { expires, control })
    }

    pub(super) const fn control(&self) -> &Arc<Control> {
        &self.control
    }

    pub(super) fn remaining(&self) -> Result<Duration, BridgeError> {
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                self.control.expire();
                BridgeError::Deadline
            })
    }

    pub(super) fn wait<Fd: std::os::fd::AsFd>(
        &self,
        descriptor: &Fd,
        events: PollFlags,
    ) -> Result<(), BridgeError> {
        let remaining = self.remaining()?;
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).map_err(|_| BridgeError::Deadline)?,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut descriptors = [
            PollFd::new(descriptor, events),
            PollFd::new(&self.control.event, PollFlags::IN),
        ];
        if poll(&mut descriptors, Some(&timeout)).map_err(|_| BridgeError::Io)? == 0 {
            self.control.expire();
            self.control.drain();
            return Err(BridgeError::Deadline);
        }
        if descriptors[1].revents().contains(PollFlags::IN) {
            self.control.drain();
            return Err(self.control.error());
        }
        let observed = descriptors[0].revents();
        if observed.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Err(BridgeError::PeerDied);
        }
        if observed.intersects(events) {
            Ok(())
        } else {
            Err(BridgeError::Io)
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn check_peer<Fd: std::os::fd::AsFd>(&self, pidfd: &Fd) -> Result<(), BridgeError> {
        self.remaining()?;
        let mut descriptors = [
            PollFd::new(pidfd, PollFlags::IN),
            PollFd::new(&self.control.event, PollFlags::IN),
        ];
        let immediate = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut descriptors, Some(&immediate)).map_err(|_| BridgeError::Io)?;
        if descriptors[1].revents().contains(PollFlags::IN) {
            self.control.drain();
            return Err(self.control.error());
        }
        if descriptors[0]
            .revents()
            .intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
        {
            Err(BridgeError::PeerDied)
        } else {
            Ok(())
        }
    }

    pub(super) fn check_socket(&self, stream: &UnixStream) -> Result<(), BridgeError> {
        self.remaining()?;
        let mut descriptors = [
            PollFd::new(stream, PollFlags::IN),
            PollFd::new(&self.control.event, PollFlags::IN),
        ];
        let immediate = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut descriptors, Some(&immediate)).map_err(|_| BridgeError::Io)?;
        if descriptors[1].revents().contains(PollFlags::IN) {
            self.control.drain();
            return Err(self.control.error());
        }
        if descriptors[0]
            .revents()
            .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
        {
            Err(BridgeError::PeerDied)
        } else {
            Ok(())
        }
    }
}
