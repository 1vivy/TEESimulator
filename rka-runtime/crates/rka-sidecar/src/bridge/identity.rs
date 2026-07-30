use std::os::unix::net::UnixStream;

use rustix::net::sockopt::socket_peercred;

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::{ReadBound, read_bounded},
    identity_source::{IdentitySource, LinuxIdentitySource},
    peer_authorization::{HeldDescriptor, PeerAuthorization},
    process_identity::{parse_cmdline, parse_start_time},
    trusted_record::{MAX_RECORD_BYTES, OpenRecord, parse_record},
};

pub(super) const BROKER_EXECUTABLE: &str = "/system/bin/app_process64";
const MAX_STAT_BYTES: usize = 4096;
const MAX_CMDLINE_BYTES: usize = 1024;

/// Closed sidecar role used by the trusted supervisor record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BrokerRole {
    /// Sidecar authenticates the donor broker server.
    Donor,
    #[doc = "Sidecar authenticates the candidate broker client."]
    Candidate,
}

impl BrokerRole {
    pub(super) const fn record(self) -> &'static str {
        match self {
            Self::Donor => "DONOR",
            Self::Candidate => "CANDIDATE",
        }
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Donor => "donor",
            Self::Candidate => "candidate",
        }
    }
}

/// Kernel-authenticated Unix peer credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PeerCredentials {
    /// Kernel-reported peer user identifier.
    pub uid: u32,
    #[doc = "Kernel-reported peer group identifier."]
    pub gid: u32,
    #[doc = "Kernel-reported peer process identifier."]
    pub pid: i32,
}

impl PeerCredentials {
    /// Reads Linux `SO_PEERCRED` through safe rustix.
    pub fn from_stream(stream: &UnixStream) -> Result<Self, BridgeError> {
        let credentials = socket_peercred(stream).map_err(|_| BridgeError::PeerIdentity)?;
        Ok(Self {
            uid: credentials.uid.as_raw(),
            gid: credentials.gid.as_raw(),
            pid: credentials.pid.as_raw_pid(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BrokerIdentity {
    pub(super) generation: u64,
    pub(super) launch_nonce: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) pid: i32,
    pub(super) start_time_ticks: u64,
    pub(super) executable_inode: u64,
    pub(super) role: BrokerRole,
}

/// Authenticates the fixed protected broker identity and kernel peer.
pub(super) fn authenticate_broker_peer(
    stream: &UnixStream,
    role: BrokerRole,
    deadline: &Deadline,
) -> Result<PeerAuthorization, BridgeError> {
    authenticate_with_source(
        &mut LinuxIdentitySource,
        AuthenticationRequest {
            stream,
            role,
            deadline,
        },
    )
}

#[derive(Clone, Copy)]
pub(super) struct AuthenticationRequest<'a> {
    pub(super) stream: &'a UnixStream,
    pub(super) role: BrokerRole,
    pub(super) deadline: &'a Deadline,
}

pub(super) fn authenticate_with_source(
    source: &mut impl IdentitySource,
    request: AuthenticationRequest<'_>,
) -> Result<PeerAuthorization, BridgeError> {
    let AuthenticationRequest {
        stream,
        role,
        deadline,
    } = request;
    let credentials = source.credentials(stream)?;
    let revalidate_socket_credentials = source.revalidates_socket_credentials();
    let OpenRecord {
        descriptor,
        snapshot,
    } = source.open_record(deadline)?;
    let mut record_bytes = read_bounded(
        &descriptor,
        deadline,
        ReadBound {
            bytes: MAX_RECORD_BYTES,
            error: BridgeError::TrustedState,
        },
    )?;
    if !snapshot.verify(&descriptor, deadline)? {
        return Err(BridgeError::TrustedState);
    }
    let parsed_identity = parse_record(&record_bytes, role);
    record_bytes.fill(0);
    let identity = parsed_identity?;
    if credentials.uid != identity.uid
        || credentials.gid != identity.gid
        || credentials.pid != identity.pid
    {
        return Err(BridgeError::PeerIdentity);
    }
    let process = source.open_process(identity.pid, deadline)?;
    deadline.check_peer(&process.pidfd)?;
    let stat = HeldDescriptor::capture(process.stat)?;
    let cmdline = HeldDescriptor::capture(process.cmdline)?;
    let mut stat_bytes = read_bounded(
        &stat.descriptor,
        deadline,
        ReadBound {
            bytes: MAX_STAT_BYTES,
            error: BridgeError::PeerIdentity,
        },
    )?;
    let parsed_start_time = parse_start_time(&stat_bytes);
    stat_bytes.fill(0);
    let start_time_ticks = parsed_start_time?;
    let mut cmdline_bytes = read_bounded(
        &cmdline.descriptor,
        deadline,
        ReadBound {
            bytes: MAX_CMDLINE_BYTES,
            error: BridgeError::PeerIdentity,
        },
    )?;
    let parsed_cmdline = parse_cmdline(&cmdline_bytes);
    cmdline_bytes.fill(0);
    let cmdline_values = parsed_cmdline?;
    let expected_cmdline = [
        BROKER_EXECUTABLE,
        "/system/bin",
        "org.matrix.TEESimulator.App",
        "--rka-role",
        role.argument(),
    ];
    if start_time_ticks != identity.start_time_ticks
        || cmdline_values
            .iter()
            .map(String::as_str)
            .ne(expected_cmdline)
    {
        return Err(BridgeError::PeerIdentity);
    }
    stat.verify(deadline, BridgeError::PeerIdentity)?;
    cmdline.verify(deadline, BridgeError::PeerIdentity)?;
    let process_directory = HeldDescriptor::capture(process.directory)?;
    let executable = HeldDescriptor::capture(process.executable)?;
    let expected_executable = HeldDescriptor::capture(process.expected_executable)?;
    if executable.snapshot.device() != expected_executable.snapshot.device()
        || executable.snapshot.inode() != expected_executable.snapshot.inode()
        || executable.snapshot.inode() != identity.executable_inode
    {
        return Err(BridgeError::PeerIdentity);
    }
    deadline.check_peer(&process.pidfd)?;
    Ok(PeerAuthorization {
        _identity: identity,
        credentials,
        revalidate_socket_credentials,
        record: HeldDescriptor::from_snapshot(descriptor, snapshot),
        process_directory,
        stat,
        cmdline,
        executable,
        expected_executable,
        pidfd: process.pidfd,
        revalidation_gate: process.revalidation_gate,
    })
}
