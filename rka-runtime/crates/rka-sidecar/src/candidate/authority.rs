use std::{
    fs,
    path::{Path, PathBuf},
};

use rka_state::PairedActivationRecord;

use super::{CandidateLayout, PairingAdmission, PairingCatalog, cleanup, migrate};
use crate::provisioning_io::FileStateStore;

#[allow(
    clippy::redundant_pub_crate,
    reason = "the donor runtime consumes this sibling candidate authority"
)]
pub(crate) enum StateAuthority {
    Legacy,
    Candidate(PathBuf),
    Invalid,
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "the donor runtime resolves this sibling candidate authority"
)]
pub(crate) fn resolve(state_root: &Path) -> StateAuthority {
    let manifest = state_root.join("state-layout-v2");
    match fs::read(&manifest) {
        Ok(encoded) => resolve_manifest(state_root, &encoded),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            resolve_without_manifest(state_root)
        }
        Err(_) => StateAuthority::Invalid,
    }
}

fn resolve_manifest(state_root: &Path, encoded: &[u8]) -> StateAuthority {
    let Some(identity) = decode_manifest(encoded) else {
        return StateAuthority::Invalid;
    };
    let Ok(catalog) = PairingCatalog::load(state_root) else {
        return StateAuthority::Invalid;
    };
    let Ok(context) = catalog.lookup_identity(identity) else {
        return StateAuthority::Invalid;
    };
    let layout = CandidateLayout::new(state_root, context.candidate());
    match migrate::validate_candidate_state(layout.root()) {
        Ok(state)
            if state.admission.candidate_identity_hash == identity
                && cleanup::record_successful_startup(state_root).is_ok() =>
        {
            StateAuthority::Candidate(layout.root().to_path_buf())
        }
        Ok(_) | Err(_) => StateAuthority::Invalid,
    }
}

fn resolve_without_manifest(state_root: &Path) -> StateAuthority {
    let store = FileStateStore::new(state_root);
    let Ok(pair) = PairedActivationRecord::load(&store) else {
        return StateAuthority::Legacy;
    };
    let admission = PairingAdmission {
        peer_spki_hash: pair.peer_spki_hash,
        profile_id_hash: pair.profile_id_hash,
        profile_epoch: pair.profile_epoch,
        candidate_identity_hash: pair.candidate_identity_hash,
    };
    let mut catalog = PairingCatalog::empty();
    if catalog.admit(admission).is_err() {
        return StateAuthority::Invalid;
    }
    let Ok(context) = catalog.lookup_identity(pair.candidate_identity_hash) else {
        return StateAuthority::Invalid;
    };
    let layout = CandidateLayout::new(state_root, context.candidate());
    if !layout.root().exists() {
        return StateAuthority::Legacy;
    }
    match migrate::validate_candidate_state(layout.root()) {
        Ok(state)
            if state.admission == admission
                && migrate::adopt_candidate(state_root, admission).is_ok()
                && cleanup::record_successful_startup(state_root).is_ok() =>
        {
            StateAuthority::Candidate(layout.root().to_path_buf())
        }
        Ok(_) | Err(_) => StateAuthority::Invalid,
    }
}

fn decode_manifest(encoded: &[u8]) -> Option<[u8; 32]> {
    if encoded.len() != 37 || encoded.get(..5) != Some(migrate::LAYOUT_MAGIC) {
        return None;
    }
    encoded.get(5..)?.try_into().ok()
}
