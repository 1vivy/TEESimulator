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
    let mut value = format!("version=1\nepoch={}\n", bundle.epoch());
    for pin in bundle.pins() {
        value.push_str("pin=");
        for byte in pin {
            write!(value, "{byte:02x}").map_err(|_| ())?;
        }
        value.push('\n');
    }
    atomic_replace(path, value.as_bytes()).map_err(|_| ())
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
