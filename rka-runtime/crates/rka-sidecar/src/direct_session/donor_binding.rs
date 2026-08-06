use std::path::{Path, PathBuf};

use rka_state::PairedActivationRecord;

use crate::{
    candidate::{
        AuthenticatedCandidateContext, CandidateLayout, PairingAdmission, PairingCatalog,
        authority::{self, StateAuthority},
    },
    direct_profile::{DirectProfile, DonorProfileSource},
    provisioning_io::FileStateStore,
};

use super::{DirectSessionError, authenticated_profile};

#[derive(Debug)]
pub(super) struct DonorProfileBinding {
    pub(super) profile: DirectProfile,
    pub(super) authenticated: AuthenticatedCandidateContext,
    pub(super) runtime_root: PathBuf,
}

pub(super) fn resolve_donor_bindings(
    state: &Path,
    source: DonorProfileSource,
    profiles: Vec<DirectProfile>,
) -> Result<Vec<DonorProfileBinding>, DirectSessionError> {
    match source {
        DonorProfileSource::Legacy => {
            let mut profiles = profiles.into_iter();
            let profile = profiles.next().ok_or(DirectSessionError::State)?;
            if profiles.next().is_some() {
                return Err(DirectSessionError::State);
            }
            let (authenticated, runtime_root) = match authority::resolve(state) {
                StateAuthority::Legacy => {
                    let pair = PairedActivationRecord::load(&FileStateStore::new(state))
                        .map_err(|_| DirectSessionError::State)?;
                    if pair.peer_spki_hash != profile.peer_pin
                        || pair.profile_epoch != profile.epoch
                    {
                        return Err(DirectSessionError::State);
                    }
                    let mut catalog = PairingCatalog::empty();
                    catalog
                        .admit(PairingAdmission {
                            peer_spki_hash: pair.peer_spki_hash,
                            profile_id_hash: pair.profile_id_hash,
                            profile_epoch: pair.profile_epoch,
                            candidate_identity_hash: pair.candidate_identity_hash,
                        })
                        .map_err(|_| DirectSessionError::State)?;
                    let authenticated = catalog
                        .lookup_profile(profile.peer_pin, profile.epoch)
                        .map_err(|_| DirectSessionError::State)?;
                    (authenticated, state.to_path_buf())
                }
                StateAuthority::Candidate(runtime_root) => {
                    (authenticated_profile(state, &profile)?, runtime_root)
                }
                StateAuthority::Invalid => return Err(DirectSessionError::State),
            };
            Ok(vec![DonorProfileBinding {
                profile,
                authenticated,
                runtime_root,
            }])
        }
        DonorProfileSource::Indexed => {
            let catalog = PairingCatalog::load(state).map_err(|_| DirectSessionError::State)?;
            profiles
                .into_iter()
                .map(|profile| {
                    let authenticated = catalog
                        .lookup_profile(profile.peer_pin, profile.epoch)
                        .map_err(|_| DirectSessionError::State)?;
                    let runtime_root = CandidateLayout::new(state, authenticated.candidate())
                        .root()
                        .to_path_buf();
                    if !runtime_root.is_dir() {
                        return Err(DirectSessionError::State);
                    }
                    Ok(DonorProfileBinding {
                        profile,
                        authenticated,
                        runtime_root,
                    })
                })
                .collect()
        }
    }
}
