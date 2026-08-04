use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use rustix::fs::{FlockOperation, flock};

use super::MigrationError;
use crate::provisioning_io::{FileStateStore, atomic_replace};

const STARTUP_MARKER: &[u8] = b"RKSS\x02";
const CLEANUP_MARKER: &[u8] = b"RKSC\x02";

/// Explicit policy for irreversible legacy-state cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum LegacyCleanup {
    /// Retains the recoverable legacy copy.
    #[default]
    Disabled,
    /// Removes legacy state after a later validated v2 startup.
    Enabled,
}

/// Removes legacy records only when explicitly enabled after a successful v2 restart.
pub fn cleanup_legacy(state_root: &Path, policy: LegacyCleanup) -> Result<bool, MigrationError> {
    match policy {
        LegacyCleanup::Disabled => return Ok(false),
        LegacyCleanup::Enabled => {}
    }
    require_marker(&state_root.join("state-layout-v2-started"), STARTUP_MARKER)?;
    let lock = cleanup_lock(state_root)?;
    flock(&lock, FlockOperation::LockExclusive).map_err(|_| MigrationError::Storage)?;
    let store = FileStateStore::new(state_root);
    remove_file(
        &store
            .record_path(b"paired-activation-v1")
            .map_err(|_| MigrationError::Storage)?,
    )?;
    remove_file(
        &store
            .record_path(b"rkp-leases-v1")
            .map_err(|_| MigrationError::Storage)?,
    )?;
    sync_directory(&state_root.join("records"))?;
    remove_file(&state_root.join("donor-transcript-v1"))?;
    fs::remove_dir_all(state_root.join("lease-chains")).map_err(|_| MigrationError::Storage)?;
    sync_directory(state_root)?;
    atomic_replace(&state_root.join("legacy-cleanup-v2"), CLEANUP_MARKER)
        .map_err(|_| MigrationError::Storage)?;
    Ok(true)
}

pub(super) fn record_successful_startup(state_root: &Path) -> Result<(), MigrationError> {
    let marker = state_root.join("state-layout-v2-started");
    match fs::read(&marker) {
        Ok(value) if value == STARTUP_MARKER => Ok(()),
        Ok(_) => Err(MigrationError::Validation),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_replace(&marker, STARTUP_MARKER).map_err(|_| MigrationError::Storage)
        }
        Err(_) => Err(MigrationError::Storage),
    }
}

fn require_marker(path: &Path, expected: &[u8]) -> Result<(), MigrationError> {
    if fs::read(path).map_err(|_| MigrationError::Validation)? != expected {
        return Err(MigrationError::Validation);
    }
    Ok(())
}

fn cleanup_lock(root: &Path) -> Result<File, MigrationError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("state-layout.lock"))
        .map_err(|_| MigrationError::Storage)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| MigrationError::Storage)?;
    Ok(file)
}

fn remove_file(path: &Path) -> Result<(), MigrationError> {
    fs::remove_file(path).map_err(|_| MigrationError::Storage)
}

fn sync_directory(path: &Path) -> Result<(), MigrationError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Storage)
}
