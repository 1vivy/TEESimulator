use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use ring::digest::{SHA256, digest};

use super::{LoadedProfiles, load_profile_file};
use crate::{
    LifecycleRole, SidecarError,
    candidate::{PairingAdmission, PairingCatalog},
};

const DONOR_PROFILE_DIRECTORY: &str = "profiles/direct.d";

pub(super) fn load_donor_profiles() -> Result<(PathBuf, LoadedProfiles), SidecarError> {
    let state_root = std::env::var_os("RKA_STATE_ROOT")
        .map(PathBuf::from)
        .ok_or(SidecarError::RuntimeContext)?;
    let expected_epoch = std::env::var("RKA_EXPECTED_PROFILE_EPOCH")
        .map_err(|_| SidecarError::RuntimeContext)?
        .parse::<u64>()
        .map_err(|_| SidecarError::RuntimeContext)?;
    let profiles = load_published_profiles(&state_root, LifecycleRole::Donor, expected_epoch)?;
    Ok((state_root, profiles))
}

pub(super) fn load_published_profiles(
    state_root: &Path,
    role: LifecycleRole,
    expected_epoch: u64,
) -> Result<LoadedProfiles, SidecarError> {
    match role {
        LifecycleRole::Donor => load_donor_profile_directory(state_root, expected_epoch),
        LifecycleRole::Candidate => load_profile_file(
            (state_root, &state_root.join("profiles/direct.conf"), role),
            expected_epoch,
        )
        .map(|profile| vec![profile]),
    }
}

fn load_donor_profile_directory(
    state_root: &Path,
    expected_epoch: u64,
) -> Result<LoadedProfiles, SidecarError> {
    let directory = state_root.join(DONOR_PROFILE_DIRECTORY);
    if !fs::symlink_metadata(&directory)
        .map_err(|_| SidecarError::RuntimeContext)?
        .file_type()
        .is_dir()
    {
        return Err(SidecarError::RuntimeContext);
    }
    let mut paths = fs::read_dir(&directory)
        .map_err(|_| SidecarError::RuntimeContext)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<PathBuf>, _>>()
        .map_err(|_| SidecarError::RuntimeContext)?;
    paths.sort_unstable();
    if paths.is_empty() {
        return Err(SidecarError::RuntimeContext);
    }

    let mut pins = PairingCatalog::empty();
    let mut profiles = Vec::with_capacity(paths.len());
    for path in paths {
        if path.extension() != Some(OsStr::new("conf")) {
            return Err(SidecarError::RuntimeContext);
        }
        let loaded = load_profile_file((state_root, &path, LifecycleRole::Donor), expected_epoch)?;
        let profile_id_hash = digest(&SHA256, &loaded.1);
        let candidate_identity_hash = digest(&SHA256, path.as_os_str().as_encoded_bytes());
        pins.admit(PairingAdmission::new(
            (
                loaded.0.peer_pin,
                profile_id_hash
                    .as_ref()
                    .try_into()
                    .map_err(|_| SidecarError::RuntimeContext)?,
                loaded.0.epoch,
            ),
            candidate_identity_hash
                .as_ref()
                .try_into()
                .map_err(|_| SidecarError::RuntimeContext)?,
        ))
        .map_err(|_| SidecarError::RuntimeContext)?;
        profiles.push(loaded);
    }
    Ok(profiles)
}
