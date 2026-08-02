//! Strict startup consumption boundary for atomically published direct profiles.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::{LifecycleRole, SidecarError};
use ring::digest::{SHA256, digest};

const MAX_PROFILE_BYTES: u64 = 4096;
const PROFILE_NAME: &str = "profiles/direct.conf";
const RECEIPT_NAME: &str = "run/direct-profile.receipt";

#[derive(Debug)]
pub(crate) struct DirectProfile {
    pub(crate) epoch: u64,
    pub(crate) endpoint: Ipv4Addr,
    pub(crate) listen_interface: Ipv4Addr,
    pub(crate) dial_mode: DialMode,
    pub(crate) peer_pin: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialMode {
    CandidateDials,
    DonorDials,
}

impl DirectProfile {
    fn parse(
        raw: &[u8],
        expected_role: LifecycleRole,
        expected_epoch: u64,
    ) -> Result<Self, SidecarError> {
        let text = std::str::from_utf8(raw).map_err(|_| SidecarError::RuntimeContext)?;
        let lines = text
            .strip_suffix('\n')
            .ok_or(SidecarError::RuntimeContext)?
            .split('\n')
            .collect::<Vec<_>>();
        let (version, role, epoch, endpoint, listen_interface, dial_mode, peer_pin, transport) =
            match lines.as_slice() {
                [version, role, epoch, endpoint, peer_pin, transport] => (
                    *version,
                    *role,
                    *epoch,
                    *endpoint,
                    *endpoint,
                    DialMode::CandidateDials,
                    *peer_pin,
                    *transport,
                ),
                [
                    version,
                    role,
                    epoch,
                    mode,
                    endpoint,
                    listen,
                    peer_pin,
                    transport,
                ] => (
                    *version,
                    *role,
                    *epoch,
                    *endpoint,
                    *listen,
                    parse_mode(mode)?,
                    *peer_pin,
                    *transport,
                ),
                _ => return Err(SidecarError::RuntimeContext),
            };
        if role != expected_role.profile_line()
            || transport != "transport=DIRECT"
            || (version == "version=1" && dial_mode != DialMode::CandidateDials)
            || (version != "version=1" && version != "version=2")
        {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_epoch = epoch
            .strip_prefix("profile_epoch=")
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<u64>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        if parsed_epoch != expected_epoch {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_endpoint = endpoint
            .strip_prefix(if version == "version=1" {
                "peer_endpoint="
            } else {
                "dial_endpoint="
            })
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<Ipv4Addr>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        let parsed_listen_interface = listen_interface
            .strip_prefix(if version == "version=1" {
                "peer_endpoint="
            } else {
                "listen_interface="
            })
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<Ipv4Addr>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        if version == "version=2"
            && (!global_ipv4(parsed_endpoint) || !global_ipv4(parsed_listen_interface))
        {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_pin = decode_pin(
            peer_pin
                .strip_prefix("peer_spki_sha256=")
                .ok_or(SidecarError::RuntimeContext)?,
        )?;
        Ok(Self {
            epoch: parsed_epoch,
            endpoint: parsed_endpoint,
            listen_interface: parsed_listen_interface,
            dial_mode,
            peer_pin: parsed_pin,
        })
    }
}

#[derive(Debug)]
struct PendingReceipt {
    path: PathBuf,
    file: File,
    committed: bool,
}

impl PendingReceipt {
    fn create(path: PathBuf) -> Result<Self, SidecarError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| SidecarError::RuntimeContext)?;
        Ok(Self {
            path,
            file,
            committed: false,
        })
    }

    fn commit(mut self, receipt: &[u8], destination: &Path) -> Result<(), SidecarError> {
        self.file
            .write_all(receipt)
            .and_then(|()| self.file.set_permissions(fs::Permissions::from_mode(0o600)))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| SidecarError::RuntimeContext)?;
        fs::rename(&self.path, destination).map_err(|_| SidecarError::RuntimeContext)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingReceipt {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Consumes the fixed direct profile and atomically publishes its redacted receipt.
pub fn consume(role: LifecycleRole) -> Result<(), SidecarError> {
    let (state_root, profile, raw) = load(role)?;
    let receipt_path =
        PathBuf::from(env::var_os("RKA_PROFILE_RECEIPT_PATH").ok_or(SidecarError::RuntimeContext)?);
    if receipt_path != state_root.join(RECEIPT_NAME) {
        return Err(SidecarError::RuntimeContext);
    }
    let receipt = startup_receipt(&profile, &raw);
    commit_receipt(&receipt_path, receipt.as_bytes())
}

/// Verifies that the donor can reach the candidate listener and commits a redacted receipt.
pub fn probe() -> Result<String, &'static str> {
    let role = env::var_os("RKA_DIRECT_PROBE_ROLE")
        .ok_or("invalid_profile")
        .and_then(|value| LifecycleRole::parse(&value).map_err(|_| "invalid_profile"))?;
    let (state_root, profile, raw) = load(role).map_err(|_| "invalid_profile")?;
    let receipt_path =
        PathBuf::from(env::var_os("RKA_DIRECT_PROBE_RECEIPT_PATH").ok_or("invalid_profile")?);
    let transactions = state_root.join("deploy-transactions");
    let receipt_parent = receipt_path.parent().ok_or("invalid_profile")?;
    if receipt_path.file_name() != Some(std::ffi::OsStr::new("direct-probe.receipt"))
        || receipt_parent.parent() != Some(transactions.as_path())
        || !receipt_parent.is_dir()
    {
        return Err("invalid_profile");
    }
    let address = SocketAddr::V4(SocketAddrV4::new(profile.endpoint, 37373));
    probe_tcp(address, std::time::Duration::from_secs(8))?;
    let profile_hash = digest(&SHA256, &raw);
    let pin_hash = digest(&SHA256, &profile.peer_pin);
    let mode = match profile.dial_mode {
        DialMode::CandidateDials => "CANDIDATE_DIALS",
        DialMode::DonorDials => "DONOR_DIALS",
    };
    let receipt = format!(
        "version=1\nprotocol=TCP_REACHABILITY\nprofile_sha256={}\nprofile_epoch={}\npeer_pin_config_sha256={}\ndial_mode={mode}\ntransport=DIRECT\n",
        hex(profile_hash.as_ref()),
        profile.epoch,
        hex(pin_hash.as_ref()),
    );
    commit_receipt(&receipt_path, receipt.as_bytes()).map_err(|_| "receipt_failed")?;
    Ok(format!(
        "RESULT=DIRECT protocol=TCP_REACHABILITY profile_sha256={}\n",
        hex(profile_hash.as_ref())
    ))
}

fn probe_tcp(address: SocketAddr, budget: std::time::Duration) -> Result<(), &'static str> {
    let socket = TcpStream::connect_timeout(&address, budget).map_err(|_| "unavailable")?;
    let _ = socket.shutdown(Shutdown::Both);
    Ok(())
}

pub(crate) fn load(role: LifecycleRole) -> Result<(PathBuf, DirectProfile, Vec<u8>), SidecarError> {
    let state_root =
        PathBuf::from(env::var_os("RKA_STATE_ROOT").ok_or(SidecarError::RuntimeContext)?);
    let profile_path =
        PathBuf::from(env::var_os("RKA_PROFILE_PATH").ok_or(SidecarError::RuntimeContext)?);
    if profile_path != state_root.join(PROFILE_NAME) {
        return Err(SidecarError::RuntimeContext);
    }
    let expected_epoch = env::var("RKA_EXPECTED_PROFILE_EPOCH")
        .map_err(|_| SidecarError::RuntimeContext)?
        .parse::<u64>()
        .map_err(|_| SidecarError::RuntimeContext)?;
    let (profile, raw) = load_from((&state_root, &profile_path, role), expected_epoch)?;
    Ok((state_root, profile, raw))
}

pub(crate) fn load_from(
    context: (&Path, &Path, LifecycleRole),
    expected_epoch: u64,
) -> Result<(DirectProfile, Vec<u8>), SidecarError> {
    let (state_root, profile_path, role) = context;
    if profile_path != state_root.join(PROFILE_NAME) {
        return Err(SidecarError::RuntimeContext);
    }
    let root_metadata =
        fs::symlink_metadata(state_root).map_err(|_| SidecarError::RuntimeContext)?;
    let profile_metadata =
        fs::symlink_metadata(profile_path).map_err(|_| SidecarError::RuntimeContext)?;
    if !root_metadata.file_type().is_dir()
        || !profile_metadata.file_type().is_file()
        || profile_metadata.len() > MAX_PROFILE_BYTES
    {
        return Err(SidecarError::RuntimeContext);
    }
    let raw = fs::read(profile_path).map_err(|_| SidecarError::RuntimeContext)?;
    let profile = DirectProfile::parse(&raw, role, expected_epoch)?;
    Ok((profile, raw))
}

#[doc(hidden)]
pub fn donor_dials(role: LifecycleRole) -> Result<bool, SidecarError> {
    load(role).map(|(_, profile, _)| profile.dial_mode == DialMode::DonorDials)
}

fn startup_receipt(profile: &DirectProfile, raw: &[u8]) -> String {
    let profile_hash = digest(&SHA256, raw);
    let pin_hash = digest(&SHA256, &profile.peer_pin);
    let mode = match profile.dial_mode {
        DialMode::CandidateDials => "CANDIDATE_DIALS",
        DialMode::DonorDials => "DONOR_DIALS",
    };
    format!(
        "version=1\nprofile_sha256={}\nprofile_epoch={}\npeer_pin_sha256={}\ndial_mode={mode}\ntransport=DIRECT\n",
        hex(profile_hash.as_ref()),
        profile.epoch,
        hex(pin_hash.as_ref())
    )
}

fn parse_mode(line: &str) -> Result<DialMode, SidecarError> {
    match line {
        "dial_mode=CANDIDATE_DIALS" => Ok(DialMode::CandidateDials),
        "dial_mode=DONOR_DIALS" => Ok(DialMode::DonorDials),
        _ => Err(SidecarError::RuntimeContext),
    }
}

const fn global_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
}

fn commit_receipt(receipt_path: &Path, receipt: &[u8]) -> Result<(), SidecarError> {
    let receipt_parent = receipt_path.parent().ok_or(SidecarError::RuntimeContext)?;
    fs::create_dir_all(receipt_parent).map_err(|_| SidecarError::RuntimeContext)?;
    let pending_path = receipt_parent.join(format!(".direct-profile.{}.tmp", std::process::id()));
    PendingReceipt::create(pending_path)?.commit(receipt, receipt_path)
}

fn decode_pin(encoded: &str) -> Result<[u8; 32], SidecarError> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SidecarError::RuntimeContext);
    }
    let mut decoded = [0_u8; 32];
    for (destination, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| SidecarError::RuntimeContext)?;
        *destination = u8::from_str_radix(text, 16).map_err(|_| SidecarError::RuntimeContext)?;
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut encoded, byte| {
        let _ = write!(encoded, "{byte:02x}");
        encoded
    })
}

#[cfg(test)]
mod probe_tests {
    use std::net::TcpListener;

    use super::probe_tcp;

    #[test]
    fn tcp_probe_accepts_an_idle_listener_without_requiring_application_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");

        probe_tcp(address, std::time::Duration::from_secs(1)).expect("probe idle listener");
    }
}
