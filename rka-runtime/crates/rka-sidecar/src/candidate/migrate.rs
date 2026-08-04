use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use rka_state::{PairedActivationRecord, RkpLeaseBatch};
use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

use super::{CandidateLayout, CatalogError, PairingAdmission, PairingCatalog, codec};
use crate::{
    donor::{lease::load_verified_chain, state::validate_existing_transcript},
    provisioning_io::{AtomicReplaceStage, FileStateStore, atomic_replace, atomic_replace_with},
};

pub(super) const LAYOUT_MAGIC: &[u8; 5] = b"RKSL\x02";
const FILE_MODE: u32 = 0o600;

/// Durable replacement checkpoint exposed for migration fault injection.
pub use crate::provisioning_io::AtomicReplaceStage as MigrationStage;

/// Closed migration failures that leave legacy state authoritative.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrationError {
    /// Legacy state or candidate state failed full validation.
    #[error("candidate state validation failed")]
    Validation,
    /// A durable filesystem operation failed.
    #[error("candidate state migration storage failed")]
    Storage,
    /// Pairing catalog construction failed.
    #[error("candidate catalog migration failed")]
    Catalog(#[from] CatalogError),
}

/// Migrates one fully validated legacy candidate while injecting durable checkpoints.
pub fn migrate_legacy_with(
    state_root: &Path,
    checkpoint: impl FnMut(AtomicReplaceStage) -> std::io::Result<()>,
) -> Result<(), MigrationError> {
    fs::create_dir_all(state_root).map_err(|_| MigrationError::Storage)?;
    let lock = migration_lock(state_root)?;
    flock(&lock, FlockOperation::LockExclusive).map_err(|_| MigrationError::Storage)?;
    let validated = validate_legacy(state_root)?;
    let staging = CandidateLayout::staging(state_root, validated.context.candidate());
    let final_layout = CandidateLayout::new(state_root, validated.context.candidate());
    remove_if_present(staging.root())?;
    if final_layout.root().exists() {
        return Err(MigrationError::Storage);
    }
    stage_candidate(state_root, &staging, &validated)?;
    fs::rename(staging.root(), final_layout.root()).map_err(|_| MigrationError::Storage)?;
    sync_directory(
        final_layout
            .candidates_root()
            .map_err(|_| MigrationError::Storage)?,
    )?;
    if let Err(error) = commit_metadata(state_root, validated.admission, checkpoint) {
        let _ = fs::remove_file(state_root.join("state-layout-v2"));
        let _ = fs::remove_dir_all(final_layout.root());
        let _ = sync_directory(final_layout.candidates_root().unwrap_or(state_root));
        return Err(error);
    }
    Ok(())
}

struct ValidatedLegacy {
    context: super::AuthenticatedCandidateContext,
    admission: PairingAdmission,
    pair_path: PathBuf,
    leases_path: PathBuf,
    transcript_path: PathBuf,
    chains: Vec<([u8; 32], Vec<u8>)>,
}

fn validate_legacy(state_root: &Path) -> Result<ValidatedLegacy, MigrationError> {
    let store = FileStateStore::new(state_root);
    let state = validate_candidate_state(state_root)?;
    Ok(ValidatedLegacy {
        context: state.context,
        admission: state.admission,
        pair_path: store
            .record_path(b"paired-activation-v1")
            .map_err(|_| MigrationError::Storage)?,
        leases_path: store
            .record_path(b"rkp-leases-v1")
            .map_err(|_| MigrationError::Storage)?,
        transcript_path: state_root.join("donor-transcript-v1"),
        chains: state.chains,
    })
}

pub(super) struct ValidatedCandidateState {
    pub(super) context: super::AuthenticatedCandidateContext,
    pub(super) admission: PairingAdmission,
    chains: Vec<([u8; 32], Vec<u8>)>,
}

pub(super) fn validate_candidate_state(
    state_root: &Path,
) -> Result<ValidatedCandidateState, MigrationError> {
    let store = FileStateStore::new(state_root);
    let pair = PairedActivationRecord::load(&store).map_err(|_| MigrationError::Validation)?;
    let leases = RkpLeaseBatch::load_active(&store).map_err(|_| MigrationError::Validation)?;
    validate_existing_transcript(state_root, pair.prior_transcript_hash)
        .map_err(|_| MigrationError::Validation)?;
    let irpc = leases
        .leases()
        .first()
        .ok_or(MigrationError::Validation)?
        .metadata()
        .irpc_identity_hash;
    if leases.leases().iter().any(|lease| {
        lease.metadata().profile_epoch != pair.profile_epoch
            || lease.metadata().irpc_identity_hash != irpc
    }) {
        return Err(MigrationError::Validation);
    }
    let mut chains = Vec::with_capacity(leases.leases().len());
    for lease in leases.leases() {
        let handle = *lease.metadata().remote_handle.as_bytes();
        let encoded = load_verified_chain(state_root, lease.metadata())
            .map_err(|_| MigrationError::Validation)?
            .concat();
        chains.push((handle, encoded));
    }
    let mut catalog = PairingCatalog::empty();
    let admission = PairingAdmission {
        peer_spki_hash: pair.peer_spki_hash,
        profile_id_hash: pair.profile_id_hash,
        profile_epoch: pair.profile_epoch,
        candidate_identity_hash: pair.candidate_identity_hash,
    };
    catalog.admit(admission)?;
    let context = catalog.lookup(
        pair.peer_spki_hash,
        pair.profile_id_hash,
        pair.profile_epoch,
    )?;
    Ok(ValidatedCandidateState {
        context,
        admission,
        chains,
    })
}

fn stage_candidate(
    state_root: &Path,
    staging: &CandidateLayout,
    validated: &ValidatedLegacy,
) -> Result<(), MigrationError> {
    staging.initialize().map_err(|_| MigrationError::Storage)?;
    let target_store = FileStateStore::new(staging.root());
    copy_file(
        &validated.pair_path,
        &target_store
            .record_path(b"paired-activation-v1")
            .map_err(|_| MigrationError::Storage)?,
    )?;
    copy_file(
        &validated.leases_path,
        &target_store
            .record_path(b"rkp-leases-v1")
            .map_err(|_| MigrationError::Storage)?,
    )?;
    copy_file(&validated.transcript_path, &staging.transcript())?;
    for (handle, encoded) in &validated.chains {
        let target = staging.root().join("lease-chains").join(hex(handle));
        atomic_replace(&target, encoded).map_err(|_| MigrationError::Storage)?;
    }
    sync_tree(staging.root())?;
    sync_directory(state_root)?;
    Ok(())
}

fn commit_metadata(
    state_root: &Path,
    admission: PairingAdmission,
    checkpoint: impl FnMut(AtomicReplaceStage) -> std::io::Result<()>,
) -> Result<(), MigrationError> {
    let catalog_path = FileStateStore::new(state_root)
        .record_path(codec::RECORD_KEY)
        .map_err(|_| MigrationError::Storage)?;
    atomic_replace(&catalog_path, &codec::encode(&[admission])?)
        .map_err(|_| MigrationError::Storage)?;
    let mut manifest = Vec::with_capacity(37);
    manifest.extend_from_slice(LAYOUT_MAGIC);
    manifest.extend_from_slice(&admission.candidate_identity_hash);
    atomic_replace_with(&state_root.join("state-layout-v2"), &manifest, checkpoint)
        .map_err(|_| MigrationError::Storage)
}

pub(super) fn adopt_candidate(
    state_root: &Path,
    admission: PairingAdmission,
) -> Result<(), MigrationError> {
    commit_metadata(state_root, admission, |_| Ok(()))
}

fn copy_file(source: &Path, target: &Path) -> Result<(), MigrationError> {
    let bytes = fs::read(source).map_err(|_| MigrationError::Storage)?;
    atomic_replace(target, &bytes).map_err(|_| MigrationError::Storage)?;
    fs::set_permissions(target, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|_| MigrationError::Storage)?;
    File::open(target)
        .and_then(|file| file.sync_all())
        .map_err(|_| MigrationError::Storage)
}

fn migration_lock(root: &Path) -> Result<File, MigrationError> {
    let path = root.join("state-layout.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| MigrationError::Storage)?;
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|_| MigrationError::Storage)?;
    Ok(file)
}

fn sync_tree(root: &Path) -> Result<(), MigrationError> {
    for name in [
        "profiles",
        "trust",
        "records",
        "request-ids",
        "lease-chains",
        "run",
    ] {
        sync_directory(&root.join(name))?;
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), MigrationError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Storage)
}

fn remove_if_present(path: &Path) -> Result<(), MigrationError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(MigrationError::Storage),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}
