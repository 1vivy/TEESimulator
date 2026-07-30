#[cfg(target_os = "linux")]
use rustix::process::{PidfdFlags, pidfd_open};
use rustix::{
    fd::OwnedFd,
    fs::{CWD, Mode, OFlags, openat},
    process::Pid,
};

use super::{
    BridgeError,
    deadline::Deadline,
    identity::{BROKER_EXECUTABLE, PeerCredentials},
    trusted_record::{OpenRecord, open_identity_record},
};

mod sealed {
    pub(in crate::bridge) trait Sealed {}
}

pub(super) trait IdentitySource: sealed::Sealed {
    fn credentials(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<PeerCredentials, BridgeError>;
    fn revalidates_socket_credentials(&self) -> bool;
    fn open_record(&mut self, deadline: &Deadline) -> Result<OpenRecord, BridgeError>;
    fn open_process(
        &mut self,
        pid: i32,
        deadline: &Deadline,
    ) -> Result<ProcessDescriptors, BridgeError>;
}

#[derive(Debug)]
pub(super) struct ProcessDescriptors {
    pub(super) pidfd: OwnedFd,
    pub(super) directory: OwnedFd,
    pub(super) stat: OwnedFd,
    pub(super) cmdline: OwnedFd,
    pub(super) executable: OwnedFd,
    pub(super) expected_executable: OwnedFd,
    pub(super) revalidation_gate: Option<OwnedFd>,
}

#[derive(Debug)]
pub(super) struct LinuxIdentitySource;

impl sealed::Sealed for LinuxIdentitySource {}

impl IdentitySource for LinuxIdentitySource {
    fn credentials(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<PeerCredentials, BridgeError> {
        PeerCredentials::from_stream(stream)
    }

    fn revalidates_socket_credentials(&self) -> bool {
        true
    }

    fn open_record(&mut self, deadline: &Deadline) -> Result<OpenRecord, BridgeError> {
        open_identity_record(deadline)
    }

    fn open_process(
        &mut self,
        pid: i32,
        deadline: &Deadline,
    ) -> Result<ProcessDescriptors, BridgeError> {
        deadline.remaining()?;
        let pid = Pid::from_raw(pid).ok_or(BridgeError::PeerIdentity)?;
        let pidfd = open_pidfd(pid)?;
        deadline.check_peer(&pidfd)?;
        let root = open_directory(CWD, "/", deadline)?;
        let proc = open_directory(&root, "proc", deadline)?;
        let directory = open_directory(&proc, pid.as_raw_nonzero().to_string(), deadline)?;
        let stat = open_readonly(&directory, "stat", deadline)?;
        let cmdline = open_readonly(&directory, "cmdline", deadline)?;
        deadline.remaining()?;
        let executable = openat(
            &directory,
            "exe",
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| BridgeError::PeerDied)?;
        let expected_executable = open_absolute_executable(deadline)?;
        deadline.check_peer(&pidfd)?;
        Ok(ProcessDescriptors {
            pidfd,
            directory,
            stat,
            cmdline,
            executable,
            expected_executable,
            revalidation_gate: None,
        })
    }
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: Pid) -> Result<OwnedFd, BridgeError> {
    pidfd_open(pid, PidfdFlags::NONBLOCK).map_err(|_| BridgeError::PeerIdentity)
}

#[cfg(not(target_os = "linux"))]
fn open_pidfd(_pid: Pid) -> Result<OwnedFd, BridgeError> {
    Err(BridgeError::PeerIdentity)
}

fn open_absolute_executable(deadline: &Deadline) -> Result<OwnedFd, BridgeError> {
    let root = open_directory(CWD, "/", deadline)?;
    let system = open_directory(&root, "system", deadline)?;
    let bin = open_directory(&system, "bin", deadline)?;
    deadline.remaining()?;
    let executable = BROKER_EXECUTABLE
        .rsplit_once('/')
        .map(|(_, name)| name)
        .ok_or(BridgeError::PeerIdentity)?;
    openat(
        &bin,
        executable,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::PeerIdentity)
}

fn open_directory<Fd: std::os::fd::AsFd, Path: rustix::path::Arg>(
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

fn open_readonly(
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

#[cfg(test)]
#[derive(Debug)]
pub(super) struct TestIdentitySource {
    record: Option<OpenRecord>,
    process: Option<ProcessDescriptors>,
}

#[cfg(test)]
impl TestIdentitySource {
    pub(super) const fn new(record: OpenRecord, process: ProcessDescriptors) -> Self {
        Self {
            record: Some(record),
            process: Some(process),
        }
    }
}

#[cfg(test)]
impl sealed::Sealed for TestIdentitySource {}

#[cfg(test)]
impl IdentitySource for TestIdentitySource {
    fn credentials(
        &self,
        _stream: &std::os::unix::net::UnixStream,
    ) -> Result<PeerCredentials, BridgeError> {
        Ok(PeerCredentials {
            uid: 0,
            gid: 0,
            pid: i32::try_from(std::process::id()).map_err(|_| BridgeError::PeerIdentity)?,
        })
    }

    fn revalidates_socket_credentials(&self) -> bool {
        false
    }

    fn open_record(&mut self, deadline: &Deadline) -> Result<OpenRecord, BridgeError> {
        deadline.remaining()?;
        self.record.take().ok_or(BridgeError::TrustedState)
    }

    fn open_process(
        &mut self,
        _pid: i32,
        deadline: &Deadline,
    ) -> Result<ProcessDescriptors, BridgeError> {
        deadline.remaining()?;
        self.process.take().ok_or(BridgeError::PeerIdentity)
    }
}
