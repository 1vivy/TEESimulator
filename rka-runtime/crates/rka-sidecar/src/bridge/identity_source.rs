use rustix::{
    fd::OwnedFd,
    fs::{CWD, Mode, OFlags, openat},
    process::Pid,
};

use super::{
    BridgeError,
    deadline::Deadline,
    identity::{BROKER_EXECUTABLE, PeerCredentials},
    process_liveness::{
        ProcessLiveness, open_directory, open_platform_liveness, open_process_executable,
        open_readonly,
    },
    record_authorization::OpenRecord,
    trusted_record::open_identity_record,
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
    pub(super) liveness: ProcessLiveness,
    pub(super) proc_root: OwnedFd,
    pub(super) process_name: String,
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
        let liveness = open_platform_liveness(pid)?;
        liveness.check(deadline)?;
        let root = open_directory(CWD, "/", deadline)?;
        let proc_root = open_directory(&root, "proc", deadline)?;
        let process_name = pid.as_raw_nonzero().to_string();
        let directory = open_directory(&proc_root, &process_name, deadline)?;
        let stat = open_readonly(&directory, "stat", deadline)?;
        let cmdline = open_readonly(&directory, "cmdline", deadline)?;
        let executable = open_process_executable(&directory, deadline)?;
        let expected_executable = open_absolute_executable(deadline)?;
        liveness.check(deadline)?;
        Ok(ProcessDescriptors {
            liveness,
            proc_root,
            process_name,
            directory,
            stat,
            cmdline,
            executable,
            expected_executable,
            revalidation_gate: None,
        })
    }
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

    pub(super) fn set_record_restore_hook(
        &mut self,
        hook: super::record_authorization::RecordRestoreHook,
    ) -> Result<(), BridgeError> {
        self.record
            .as_mut()
            .ok_or(BridgeError::TrustedState)?
            .restore_after_read = Some(hook);
        Ok(())
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
