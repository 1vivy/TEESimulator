use std::{
    env,
    fmt::Write as _,
    fs,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use rka_rkp::{ProvisioningSession, RootBundle, RootRotationAuthorization, RootTrustManager};
use rustix::fs::{FlockOperation, flock};

use crate::{ProvisioningRunError, provisioning_io::atomic_replace};

const MAX_BUNDLE_BYTES: u64 = 4096;
static TRUST_RUNTIME: OnceLock<TrustRuntime> = OnceLock::new();

#[derive(Debug)]
struct RotationRequest {
    epoch: u64,
    pins: Vec<[u8; 32]>,
    authorization: Option<RootRotationAuthorization>,
}

#[derive(Debug)]
struct TrustRuntime {
    manager: RootTrustManager,
    root: PathBuf,
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling provisioning coordinator owns this private guard"
)]
pub(crate) struct TrustGuard {
    session: ProvisioningSession<'static>,
    _lock: File,
}

impl TrustGuard {
    pub(crate) const fn roots(&self) -> &RootBundle {
        self.session.roots()
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling provisioning coordinator enters this private runtime"
)]
pub(crate) fn begin(epoch: u64, root: &Path) -> Result<TrustGuard, ProvisioningRunError> {
    let runtime = shared(epoch, root)?;
    let lock = open_lock(root)?;
    flock(&lock, FlockOperation::LockShared).map_err(|_| ProvisioningRunError::Validation)?;
    let session = runtime
        .manager
        .begin()
        .map_err(|_| ProvisioningRunError::Validation)?;
    if session.roots().epoch() != epoch {
        return Err(ProvisioningRunError::Configuration);
    }
    Ok(TrustGuard {
        session,
        _lock: lock,
    })
}

/// Executes the fixed root-bundle rotation command from root-owned state.
pub fn dispatch_rotation() -> Result<(), ProvisioningRunError> {
    let root = env::var_os("RKA_STATE_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ProvisioningRunError::Configuration)?;
    let request = parse_request(&root.join("trust/root-bundle.next"))?;
    let runtime = shared(request.epoch.saturating_sub(1), &root)?;
    let lock = open_lock(&root)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ProvisioningRunError::Validation)?;
    runtime
        .manager
        .pause_rotate_and_persist(
            request.epoch,
            request.pins,
            request.authorization.as_ref(),
            |next| persist(&runtime.root.join("trust/root-bundle.active"), next),
        )
        .map_err(|_| ProvisioningRunError::Validation)
}

/// Returns the atomically committed trust/profile epoch for a new process session.
pub fn committed_profile_epoch() -> Result<u64, ProvisioningRunError> {
    let root = env::var_os("RKA_STATE_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ProvisioningRunError::Configuration)?;
    load_active(&root)?
        .map(|bundle| bundle.epoch())
        .ok_or(ProvisioningRunError::Configuration)
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling production config resolves the durable trust/profile epoch"
)]
pub(crate) fn effective_profile_epoch(
    root: &Path,
    bootstrap_epoch: u64,
) -> Result<u64, ProvisioningRunError> {
    Ok(load_active(root)?.map_or(bootstrap_epoch, |bundle| bundle.epoch()))
}

fn open_lock(root: &Path) -> Result<File, ProvisioningRunError> {
    let directory = root.join("trust");
    fs::create_dir_all(&directory).map_err(|_| ProvisioningRunError::Configuration)?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("root-bundle.lock"))
        .map_err(|_| ProvisioningRunError::Configuration)
}

fn shared(epoch: u64, root: &Path) -> Result<&'static TrustRuntime, ProvisioningRunError> {
    if let Some(runtime) = TRUST_RUNTIME.get() {
        if runtime.root != root {
            return Err(ProvisioningRunError::Configuration);
        }
        return Ok(runtime);
    }
    let bundle = load_active(root)?.unwrap_or_else(|| initial_bundle(epoch));
    let value = TrustRuntime {
        manager: RootTrustManager::new(bundle),
        root: root.to_path_buf(),
    };
    let _existing = TRUST_RUNTIME.set(value);
    TRUST_RUNTIME
        .get()
        .ok_or(ProvisioningRunError::Configuration)
}

fn initial_bundle(epoch: u64) -> RootBundle {
    rotation_key().map_or_else(
        || RootBundle::production(epoch),
        |key| RootBundle::production_with_rotation_key(epoch, key),
    )
}

fn rotation_key() -> Option<[u8; 32]> {
    env::var("RKA_ROOT_ROTATION_PUBLIC_KEY")
        .ok()
        .and_then(|value| decode_array(&value))
}

fn load_active(root: &Path) -> Result<Option<RootBundle>, ProvisioningRunError> {
    let path = root.join("trust/root-bundle.active");
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_BUNDLE_BYTES => {
            let request = parse_request(&path)?;
            let bundle = match rotation_key() {
                Some(key) => RootBundle::with_rotation_key(request.epoch, request.pins, key),
                None => RootBundle::pinned(request.epoch, request.pins),
            };
            Ok(Some(bundle))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) | Err(_) => Err(ProvisioningRunError::Configuration),
    }
}

fn parse_request(path: &Path) -> Result<RotationRequest, ProvisioningRunError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProvisioningRunError::Configuration)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BUNDLE_BYTES {
        return Err(ProvisioningRunError::Configuration);
    }
    let text = fs::read_to_string(path).map_err(|_| ProvisioningRunError::Configuration)?;
    let mut epoch = None;
    let mut version = false;
    let mut pins = Vec::new();
    let mut authorization = None;
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or(ProvisioningRunError::Configuration)?;
        match name {
            "version" if value == "1" && !version => version = true,
            "epoch" if epoch.is_none() => epoch = value.parse().ok(),
            "pin" => pins.push(decode_array(value).ok_or(ProvisioningRunError::Configuration)?),
            "authorization" if authorization.is_none() => {
                authorization = Some(RootRotationAuthorization::new(
                    decode_array(value).ok_or(ProvisioningRunError::Configuration)?,
                ));
            }
            _ => return Err(ProvisioningRunError::Configuration),
        }
    }
    if !version || pins.is_empty() || pins.len() > 20 {
        return Err(ProvisioningRunError::Configuration);
    }
    Ok(RotationRequest {
        epoch: epoch.ok_or(ProvisioningRunError::Configuration)?,
        pins,
        authorization,
    })
}

fn persist(path: &Path, bundle: &RootBundle) -> Result<(), ()> {
    persist_with(path, bundle, atomic_replace)
}

fn persist_with(
    path: &Path,
    bundle: &RootBundle,
    replace: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
) -> Result<(), ()> {
    let mut value = format!("version=1\nepoch={}\n", bundle.epoch());
    for pin in bundle.pins() {
        value.push_str("pin=");
        for byte in pin {
            write!(value, "{byte:02x}").map_err(|_| ())?;
        }
        value.push('\n');
    }
    match replace(path, value.as_bytes()) {
        Ok(()) => Ok(()),
        Err(_) if active_matches(path, bundle) => Ok(()),
        Err(_) => Err(()),
    }
}

fn active_matches(path: &Path, bundle: &RootBundle) -> bool {
    parse_request(path).is_ok_and(|request| {
        let mut pins = request.pins;
        pins.sort_unstable();
        request.epoch == bundle.epoch() && pins == bundle.pins()
    })
}

fn decode_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index.checked_mul(2)?;
        *byte = u8::from_str_radix(value.get(offset..offset.checked_add(2)?)?, 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning_io::{AtomicReplaceStage, atomic_replace_with};
    use rka_rkp::RootTrustManager;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn every_atomic_stage_leaves_manager_and_record_on_one_coherent_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        for failed_stage in AtomicReplaceStage::ALL {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let root = env::temp_dir().join(format!(
                "rka-trust-atomic-{}-{nonce}-{:?}",
                std::process::id(),
                failed_stage
            ));
            let active = root.join("trust/root-bundle.active");
            let old = RootBundle::pinned(1, vec![[1; 32], [2; 32]]);
            persist(&active, &old).map_err(|()| "initial persist")?;
            let manager = RootTrustManager::new(old);
            let rotated =
                manager.pause_rotate_and_persist(2, vec![[2; 32], [3; 32]], None, |next| {
                    persist_with(&active, next, |path, value| {
                        atomic_replace_with(path, value, |stage| {
                            if stage == failed_stage {
                                Err(std::io::Error::other("injected"))
                            } else {
                                Ok(())
                            }
                        })
                    })
                });
            let memory_epoch = manager.begin()?.roots().epoch();
            let disk_epoch = parse_request(&active)?.epoch;
            assert_eq!(memory_epoch, disk_epoch);
            if failed_stage == AtomicReplaceStage::ParentSync {
                assert!(rotated.is_ok());
                assert_eq!(disk_epoch, 2);
            } else {
                assert!(rotated.is_err());
                assert_eq!(disk_epoch, 1);
            }
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
