use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use ring::digest::{SHA256, digest};

use super::{DialMode, DirectProfile, load};
use crate::{LifecycleRole, SidecarError};

const RECEIPT_NAME: &str = "run/direct-profile.receipt";

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

/// Verifies candidate reachability and commits a redacted receipt.
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
    probe_tcp(
        SocketAddr::V4(SocketAddrV4::new(profile.endpoint, 37_373)),
        std::time::Duration::from_secs(8),
    )?;
    let profile_hash = digest(&SHA256, &raw);
    let pin_hash = digest(&SHA256, &profile.peer_pin);
    let mode = mode(profile.dial_mode);
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

fn startup_receipt(profile: &DirectProfile, raw: &[u8]) -> String {
    let profile_hash = digest(&SHA256, raw);
    let pin_hash = digest(&SHA256, &profile.peer_pin);
    let mode = mode(profile.dial_mode);
    format!(
        "version=1\nprofile_sha256={}\nprofile_epoch={}\npeer_pin_sha256={}\ndial_mode={mode}\ntransport=DIRECT\n",
        hex(profile_hash.as_ref()),
        profile.epoch,
        hex(pin_hash.as_ref())
    )
}

const fn mode(mode: DialMode) -> &'static str {
    match mode {
        DialMode::CandidateDials => "CANDIDATE_DIALS",
        DialMode::DonorDials => "DONOR_DIALS",
    }
}

fn probe_tcp(address: SocketAddr, budget: std::time::Duration) -> Result<(), &'static str> {
    let socket = TcpStream::connect_timeout(&address, budget).map_err(|_| "unavailable")?;
    let _ = socket.shutdown(Shutdown::Both);
    Ok(())
}

fn commit_receipt(receipt_path: &Path, receipt: &[u8]) -> Result<(), SidecarError> {
    let receipt_parent = receipt_path.parent().ok_or(SidecarError::RuntimeContext)?;
    fs::create_dir_all(receipt_parent).map_err(|_| SidecarError::RuntimeContext)?;
    let pending_path = receipt_parent.join(format!(".direct-profile.{}.tmp", std::process::id()));
    PendingReceipt::create(pending_path)?.commit(receipt, receipt_path)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut encoded, byte| {
        let _ = write!(encoded, "{byte:02x}");
        encoded
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::probe_tcp;

    #[test]
    fn tcp_probe_accepts_an_idle_listener_without_requiring_application_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");

        probe_tcp(address, std::time::Duration::from_secs(1)).expect("probe idle listener");
    }
}
