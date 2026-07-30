use std::os::unix::net::UnixStream;

use rustix::fd::OwnedFd;

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::{DescriptorSnapshot, ReadBound, read_bounded},
    identity::{
        BROKER_EXECUTABLE, BrokerIdentity, MAX_CMDLINE_BYTES, MAX_STAT_BYTES, PeerCredentials,
    },
    process_identity::{parse_cmdline, parse_start_time},
    process_liveness::{ProcessLiveness, open_directory, open_process_executable, open_readonly},
};

#[derive(Debug)]
pub(super) struct HeldDescriptor {
    pub(super) descriptor: OwnedFd,
    pub(super) snapshot: DescriptorSnapshot,
}

impl HeldDescriptor {
    pub(super) fn capture(descriptor: OwnedFd) -> Result<Self, BridgeError> {
        let snapshot = DescriptorSnapshot::capture(&descriptor)?;
        Ok(Self {
            descriptor,
            snapshot,
        })
    }

    pub(super) const fn from_snapshot(descriptor: OwnedFd, snapshot: DescriptorSnapshot) -> Self {
        Self {
            descriptor,
            snapshot,
        }
    }

    pub(super) fn verify(
        &self,
        deadline: &Deadline,
        error: BridgeError,
    ) -> Result<(), BridgeError> {
        if self.snapshot.verify(&self.descriptor, deadline)? {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn verify_object(&self, deadline: &Deadline, error: BridgeError) -> Result<(), BridgeError> {
        if self.snapshot.verify_object(&self.descriptor, deadline)? {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[derive(Debug)]
pub(super) struct ProcDirectoryAuthorization {
    pub(super) proc_root: HeldDescriptor,
    pub(super) process_name: String,
    pub(super) directory: HeldDescriptor,
    pub(super) stat: HeldDescriptor,
    pub(super) cmdline: HeldDescriptor,
    pub(super) executable: HeldDescriptor,
    pub(super) expected_executable: HeldDescriptor,
}

struct FreshProcessIdentity<'a> {
    stat: &'a OwnedFd,
    cmdline: &'a OwnedFd,
}

impl ProcDirectoryAuthorization {
    fn revalidate(
        &self,
        identity: &BrokerIdentity,
        deadline: &Deadline,
    ) -> Result<(), BridgeError> {
        self.proc_root
            .verify_object(deadline, BridgeError::PeerIdentity)?;
        self.directory
            .verify_object(deadline, BridgeError::PeerDied)?;
        self.stat.verify(deadline, BridgeError::PeerIdentity)?;
        self.cmdline.verify(deadline, BridgeError::PeerIdentity)?;
        self.executable
            .verify(deadline, BridgeError::PeerIdentity)?;
        self.expected_executable
            .verify(deadline, BridgeError::PeerIdentity)?;
        self.verify_current_process_name(deadline)?;
        let stat = open_readonly(&self.directory.descriptor, "stat", deadline)?;
        let cmdline = open_readonly(&self.directory.descriptor, "cmdline", deadline)?;
        Self::revalidate_process_identity(
            &FreshProcessIdentity {
                stat: &stat,
                cmdline: &cmdline,
            },
            identity,
            deadline,
        )?;
        let executable = open_process_executable(&self.directory.descriptor, deadline)?;
        let executable_snapshot = DescriptorSnapshot::capture(&executable)?;
        deadline.remaining()?;
        if !self.executable.snapshot.same_object(executable_snapshot)
            || !self
                .expected_executable
                .snapshot
                .same_object(executable_snapshot)
            || executable_snapshot.inode() != identity.executable_inode
        {
            return Err(BridgeError::PeerIdentity);
        }
        self.verify_current_process_name(deadline)
    }

    fn verify_current_process_name(&self, deadline: &Deadline) -> Result<(), BridgeError> {
        let current_directory =
            open_directory(&self.proc_root.descriptor, &self.process_name, deadline)?;
        let current_snapshot = DescriptorSnapshot::capture(&current_directory)?;
        deadline.remaining()?;
        if !self.directory.snapshot.same_object(current_snapshot) {
            return Err(BridgeError::PeerDied);
        }
        Ok(())
    }

    fn revalidate_process_identity(
        descriptors: &FreshProcessIdentity<'_>,
        identity: &BrokerIdentity,
        deadline: &Deadline,
    ) -> Result<(), BridgeError> {
        let mut stat_bytes = read_bounded(
            descriptors.stat,
            deadline,
            ReadBound {
                bytes: MAX_STAT_BYTES,
                error: BridgeError::PeerIdentity,
            },
        )?;
        let start_time = parse_start_time(&stat_bytes);
        stat_bytes.fill(0);
        let mut cmdline_bytes = read_bounded(
            descriptors.cmdline,
            deadline,
            ReadBound {
                bytes: MAX_CMDLINE_BYTES,
                error: BridgeError::PeerIdentity,
            },
        )?;
        let cmdline_values = parse_cmdline(&cmdline_bytes);
        cmdline_bytes.fill(0);
        let expected = [
            BROKER_EXECUTABLE,
            "/system/bin",
            "org.matrix.TEESimulator.App",
            "--rka-role",
            identity.role.argument(),
        ];
        if start_time? == identity.start_time_ticks
            && cmdline_values?.iter().map(String::as_str).eq(expected)
        {
            Ok(())
        } else {
            Err(BridgeError::PeerIdentity)
        }
    }
}

#[derive(Debug)]
pub(super) struct PeerAuthorization {
    pub(super) identity: BrokerIdentity,
    pub(super) credentials: PeerCredentials,
    pub(super) revalidate_socket_credentials: bool,
    pub(super) record: HeldDescriptor,
    pub(super) process: ProcDirectoryAuthorization,
    pub(super) liveness: ProcessLiveness,
    pub(super) revalidation_gate: Option<OwnedFd>,
}

impl PeerAuthorization {
    pub(super) fn revalidate(
        &self,
        stream: &UnixStream,
        deadline: &Deadline,
    ) -> Result<(), BridgeError> {
        deadline.remaining()?;
        deadline.check_socket(stream)?;
        if self.revalidate_socket_credentials
            && PeerCredentials::from_stream(stream)? != self.credentials
        {
            return Err(BridgeError::PeerIdentity);
        }
        if let Some(gate) = self.revalidation_gate.as_ref() {
            deadline.wait(gate, rustix::event::PollFlags::IN)?;
        }
        self.liveness.check(deadline)?;
        self.record.verify(deadline, BridgeError::TrustedState)?;
        self.process.revalidate(&self.identity, deadline)?;
        self.liveness.check(deadline)?;
        deadline.check_socket(stream)
    }
}
