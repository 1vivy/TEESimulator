use std::os::unix::net::UnixStream;

use rustix::fd::OwnedFd;

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::DescriptorSnapshot,
    identity::{BrokerIdentity, PeerCredentials},
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
}

#[derive(Debug)]
pub(super) struct PeerAuthorization {
    pub(super) _identity: BrokerIdentity,
    pub(super) credentials: PeerCredentials,
    pub(super) revalidate_socket_credentials: bool,
    pub(super) record: HeldDescriptor,
    pub(super) process_directory: HeldDescriptor,
    pub(super) stat: HeldDescriptor,
    pub(super) cmdline: HeldDescriptor,
    pub(super) executable: HeldDescriptor,
    pub(super) expected_executable: HeldDescriptor,
    pub(super) pidfd: OwnedFd,
    pub(super) revalidation_gate: Option<OwnedFd>,
}

impl PeerAuthorization {
    pub(super) fn revalidate(
        &self,
        stream: &UnixStream,
        deadline: &Deadline,
    ) -> Result<(), BridgeError> {
        deadline.remaining()?;
        if self.revalidate_socket_credentials
            && PeerCredentials::from_stream(stream)? != self.credentials
        {
            return Err(BridgeError::PeerIdentity);
        }
        if let Some(gate) = self.revalidation_gate.as_ref() {
            deadline.wait(gate, rustix::event::PollFlags::IN)?;
        }
        deadline.check_peer(&self.pidfd)?;
        self.record.verify(deadline, BridgeError::TrustedState)?;
        self.process_directory
            .verify(deadline, BridgeError::PeerIdentity)?;
        self.stat.verify(deadline, BridgeError::PeerIdentity)?;
        self.cmdline.verify(deadline, BridgeError::PeerIdentity)?;
        self.executable
            .verify(deadline, BridgeError::PeerIdentity)?;
        self.expected_executable
            .verify(deadline, BridgeError::PeerIdentity)?;
        deadline.check_peer(&self.pidfd)
    }
}
