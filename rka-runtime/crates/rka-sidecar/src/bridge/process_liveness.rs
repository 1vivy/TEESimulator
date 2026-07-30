#[cfg(target_os = "linux")]
use rustix::process::{PidfdFlags, pidfd_open};
use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags, openat},
    process::Pid,
};

use super::{BridgeError, deadline::Deadline};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessStrategy {
    #[cfg(target_os = "linux")]
    Pidfd,
    #[cfg(target_os = "android")]
    ProcDirectory,
}

#[cfg(target_os = "linux")]
const PLATFORM_PROCESS_STRATEGY: ProcessStrategy = ProcessStrategy::Pidfd;
#[cfg(target_os = "android")]
const PLATFORM_PROCESS_STRATEGY: ProcessStrategy = ProcessStrategy::ProcDirectory;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
compile_error!("rka-sidecar process liveness is implemented only for Android and Linux");
#[cfg(target_os = "android")]
const _: () = assert!(matches!(
    PLATFORM_PROCESS_STRATEGY,
    ProcessStrategy::ProcDirectory
));

#[derive(Debug)]
pub(super) enum ProcessLiveness {
    #[cfg(target_os = "linux")]
    Pidfd(OwnedFd),
    #[cfg(any(target_os = "android", test))]
    ProcDirectory,
}

impl ProcessLiveness {
    pub(super) fn check(&self, deadline: &Deadline) -> Result<(), BridgeError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Pidfd(pidfd) => deadline.check_peer(pidfd),
            #[cfg(any(target_os = "android", test))]
            Self::ProcDirectory => deadline.remaining().map(|_| ()),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn open_platform_liveness(pid: Pid) -> Result<ProcessLiveness, BridgeError> {
    match PLATFORM_PROCESS_STRATEGY {
        ProcessStrategy::Pidfd => pidfd_open(pid, PidfdFlags::NONBLOCK)
            .map(ProcessLiveness::Pidfd)
            .map_err(|_| BridgeError::PeerIdentity),
    }
}

#[cfg(target_os = "android")]
pub(super) fn open_platform_liveness(_pid: Pid) -> Result<ProcessLiveness, BridgeError> {
    match PLATFORM_PROCESS_STRATEGY {
        ProcessStrategy::ProcDirectory => Ok(ProcessLiveness::ProcDirectory),
    }
}

pub(super) fn open_directory<Fd: std::os::fd::AsFd, Path: rustix::path::Arg>(
    parent: Fd,
    component: Path,
    deadline: &Deadline,
) -> Result<OwnedFd, BridgeError> {
    deadline.remaining()?;
    openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::PeerDied)
}

pub(super) fn open_readonly(
    parent: &impl std::os::fd::AsFd,
    name: &str,
    deadline: &Deadline,
) -> Result<OwnedFd, BridgeError> {
    deadline.remaining()?;
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::PeerDied)
}

pub(super) fn open_process_executable(
    directory: &impl std::os::fd::AsFd,
    deadline: &Deadline,
) -> Result<OwnedFd, BridgeError> {
    deadline.remaining()?;
    openat(
        directory,
        "exe",
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::PeerDied)
}
