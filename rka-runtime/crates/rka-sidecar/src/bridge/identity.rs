use std::{
    fs,
    os::unix::{fs::MetadataExt, net::UnixStream},
};

use rustix::net::sockopt::socket_peercred;

use super::{BridgeError, trusted_record::read_identity_record};

pub(super) const BROKER_EXECUTABLE: &str = "/system/bin/app_process64";

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

/// Authenticated broker identity that can be revalidated before exposure.
#[derive(Debug)]
pub struct AuthenticatedBroker {
    identity: BrokerIdentity,
    role: BrokerRole,
}

impl AuthenticatedBroker {
    #[doc = "Returns the supervisor reconnect generation."]
    pub const fn generation(&self) -> u64 {
        self.identity.generation
    }

    #[doc = "Revalidates record, credentials, and procfs identity."]
    pub fn revalidate(&self, stream: &UnixStream) -> Result<(), BridgeError> {
        let current = read_identity_record(self.role)?;
        if current != self.identity {
            return Err(BridgeError::TrustedState);
        }
        validate_peer(stream, &current)
    }
}

/// Authenticates the fixed protected broker identity and kernel peer.
pub fn authenticate_broker_peer(
    stream: &UnixStream,
    role: BrokerRole,
) -> Result<AuthenticatedBroker, BridgeError> {
    let identity = read_identity_record(role)?;
    validate_peer(stream, &identity)?;
    Ok(AuthenticatedBroker { identity, role })
}

fn validate_peer(stream: &UnixStream, identity: &BrokerIdentity) -> Result<(), BridgeError> {
    let credentials = PeerCredentials::from_stream(stream)?;
    if credentials.uid != identity.uid
        || credentials.gid != identity.gid
        || credentials.pid != identity.pid
    {
        return Err(BridgeError::PeerIdentity);
    }
    let observed = process_identity(identity.pid)?;
    let expected_cmdline = [
        BROKER_EXECUTABLE,
        "/system/bin",
        "org.matrix.TEESimulator.App",
        "--rka-role",
        identity.role.argument(),
    ];
    if observed.start_time_ticks != identity.start_time_ticks
        || observed
            .cmdline
            .iter()
            .map(String::as_str)
            .ne(expected_cmdline)
        || observed.executable_path != BROKER_EXECUTABLE
        || observed.executable_inode != identity.executable_inode
    {
        return Err(BridgeError::PeerIdentity);
    }
    Ok(())
}

struct ProcessIdentity {
    start_time_ticks: u64,
    cmdline: Vec<String>,
    executable_path: String,
    executable_inode: u64,
}

fn process_identity(pid: i32) -> Result<ProcessIdentity, BridgeError> {
    let root = format!("/proc/{pid}");
    let stat = fs::read_to_string(format!("{root}/stat")).map_err(|_| BridgeError::PeerDied)?;
    let close = stat.rfind(')').ok_or(BridgeError::PeerIdentity)?;
    let fields = stat
        .get(close.checked_add(2).ok_or(BridgeError::PeerIdentity)?..)
        .ok_or(BridgeError::PeerIdentity)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let start_time_ticks = fields
        .get(19)
        .ok_or(BridgeError::PeerIdentity)?
        .parse::<u64>()
        .map_err(|_| BridgeError::PeerIdentity)?;
    let raw_cmdline = fs::read(format!("{root}/cmdline")).map_err(|_| BridgeError::PeerDied)?;
    let cmdline = parse_cmdline(&raw_cmdline)?;
    let executable = fs::read_link(format!("{root}/exe")).map_err(|_| BridgeError::PeerDied)?;
    let metadata = fs::metadata(&executable).map_err(|_| BridgeError::PeerDied)?;
    let executable_path = executable
        .to_str()
        .ok_or(BridgeError::PeerIdentity)?
        .to_owned();
    Ok(ProcessIdentity {
        start_time_ticks,
        cmdline,
        executable_path,
        executable_inode: metadata.ino(),
    })
}

fn parse_cmdline(bytes: &[u8]) -> Result<Vec<String>, BridgeError> {
    if bytes.is_empty() || bytes.last().copied() != Some(0) {
        return Err(BridgeError::PeerIdentity);
    }
    let mut values = Vec::new();
    let content = bytes
        .get(..bytes.len().saturating_sub(1))
        .ok_or(BridgeError::PeerIdentity)?;
    for value in content.split(|byte| *byte == 0) {
        if value.is_empty() {
            return Err(BridgeError::PeerIdentity);
        }
        values.push(
            std::str::from_utf8(value)
                .map_err(|_| BridgeError::PeerIdentity)?
                .to_owned(),
        );
    }
    if values.is_empty() {
        return Err(BridgeError::PeerIdentity);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_procfs_parser_handles_parentheses_and_exact_start_time() {
        let stat = "42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99";
        let close = stat.rfind(')').unwrap_or_default();
        let fields = stat
            .get(close.saturating_add(2)..)
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(fields.get(19).copied(), Some("99"));
    }

    #[test]
    fn bridge_procfs_cmdline_rejects_empty_unterminated_and_empty_argument() {
        assert_eq!(parse_cmdline(b""), Err(BridgeError::PeerIdentity));
        assert_eq!(parse_cmdline(b"broker"), Err(BridgeError::PeerIdentity));
        assert_eq!(
            parse_cmdline(b"broker\0\0role\0"),
            Err(BridgeError::PeerIdentity)
        );
    }
}
