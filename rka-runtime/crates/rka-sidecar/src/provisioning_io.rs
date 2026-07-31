use std::{
    env,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use rka_rkp::{
    ClientError,
    challenge::{AttemptJournal, EffectiveBaseStore},
    config::{BaseUrl, ProvisioningInfo},
};
use rka_state::{StateError, StateStore};

const MAX_JOURNAL_BYTES: u64 = 131_072;

#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling production coordinator consumes this private configuration"
)]
pub(crate) struct ProductionConfig {
    pub(crate) socket: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) validator_key: PathBuf,
    pub(crate) base: BaseUrl,
    pub(crate) info: ProvisioningInfo,
    pub(crate) fingerprint: String,
    pub(crate) epoch: u64,
    pub(crate) key_count: u8,
}

impl ProductionConfig {
    pub(crate) fn load() -> Result<Self, crate::ProvisioningRunError> {
        let socket = required_path("RKA_DONOR_SOCKET")?;
        let state_root = required_path("RKA_STATE_ROOT")?;
        let validator_key = required_path("RKA_VALIDATOR_PKCS8")?;
        let base = BaseUrl::parse(&required_text("RKA_PROVISIONING_BASE")?)
            .map_err(|_| crate::ProvisioningRunError::Configuration)?;
        let fingerprint = required_text("RKA_BUILD_FINGERPRINT")?;
        let epoch = parse_u64("RKA_PROFILE_EPOCH")?;
        let key_count = u8::try_from(parse_u64("RKA_KEY_COUNT")?)
            .ok()
            .filter(|count| (1..=20).contains(count))
            .ok_or(crate::ProvisioningRunError::Configuration)?;
        let info = ProvisioningInfo::new(&fingerprint, epoch, 3)
            .map_err(|_| crate::ProvisioningRunError::Configuration)?;
        Ok(Self {
            socket,
            state_root,
            validator_key,
            base,
            info,
            fingerprint,
            epoch,
            key_count,
        })
    }
}

#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling production coordinator owns this private adapter"
)]
pub(crate) struct FileBaseStore(PathBuf);

impl FileBaseStore {
    pub(crate) fn new(root: &Path) -> Self {
        Self(root.join("effective-base"))
    }
}

impl EffectiveBaseStore for FileBaseStore {
    fn load(&self) -> Option<BaseUrl> {
        let value = fs::read_to_string(&self.0).ok()?;
        BaseUrl::parse(value.trim_end()).ok()
    }

    fn store(&mut self, base: &BaseUrl) -> Result<(), ClientError> {
        atomic_replace(&self.0, base.as_str().as_bytes()).map_err(|_| ClientError::Store)
    }
}

#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling production coordinator owns this private adapter"
)]
pub(crate) struct FileAttemptJournal(PathBuf);

impl FileAttemptJournal {
    pub(crate) fn new(root: &Path) -> Self {
        Self(root.join("request-ids"))
    }
}

impl AttemptJournal for FileAttemptJournal {
    fn record(&mut self, request_id: &str) -> Result<bool, ClientError> {
        let mut existing = String::new();
        match File::open(&self.0) {
            Ok(mut file) => {
                if file.metadata().map_err(|_| ClientError::Journal)?.len() > MAX_JOURNAL_BYTES {
                    return Err(ClientError::Journal);
                }
                file.read_to_string(&mut existing)
                    .map_err(|_| ClientError::Journal)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ClientError::Journal),
        }
        if existing.lines().any(|line| line == request_id) {
            return Ok(false);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .map_err(|_| ClientError::Journal)?;
        writeln!(file, "{request_id}").map_err(|_| ClientError::Journal)?;
        file.sync_all().map_err(|_| ClientError::Journal)?;
        Ok(true)
    }
}

#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling production coordinator owns this private adapter"
)]
pub(crate) struct FileStateStore(PathBuf);

impl FileStateStore {
    pub(crate) fn new(root: &Path) -> Self {
        Self(root.join("records"))
    }
}

impl StateStore for FileStateStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = fs::read(self.path(key)?).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StateError::Missing
            } else {
                StateError::Storage
            }
        })?;
        if value.len() > output.len() {
            return Err(StateError::Capacity);
        }
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        fs::create_dir_all(&self.0).map_err(|_| StateError::Storage)?;
        atomic_replace(&self.path(key)?, value).map_err(|_| StateError::Storage)
    }
}

impl FileStateStore {
    fn path(&self, key: &[u8]) -> Result<PathBuf, StateError> {
        if key.is_empty() || key.len() > 64 {
            return Err(StateError::Storage);
        }
        let name = key.iter().fold(
            String::with_capacity(key.len().saturating_mul(2)),
            |mut encoded, byte| {
                let _ = write!(encoded, "{byte:02x}");
                encoded
            },
        );
        Ok(self.0.join(name))
    }
}

fn atomic_replace(path: &Path, value: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(value)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()
}

fn required_path(name: &str) -> Result<PathBuf, crate::ProvisioningRunError> {
    let value = PathBuf::from(required_text(name)?);
    if !value.is_absolute() {
        return Err(crate::ProvisioningRunError::Configuration);
    }
    Ok(value)
}

fn required_text(name: &str) -> Result<String, crate::ProvisioningRunError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= 4096 && !value.contains('\0'))
        .ok_or(crate::ProvisioningRunError::Configuration)
}

fn parse_u64(name: &str) -> Result<u64, crate::ProvisioningRunError> {
    required_text(name)?
        .parse()
        .map_err(|_| crate::ProvisioningRunError::Configuration)
}
