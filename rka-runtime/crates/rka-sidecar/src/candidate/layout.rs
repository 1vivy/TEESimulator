use std::{
    fmt::Write as _,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use super::CandidateId;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// Candidate-specific durable path resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLayout {
    root: PathBuf,
}

impl CandidateLayout {
    /// Resolves one final candidate root from its admitted identity.
    #[must_use]
    pub fn new(state_root: &Path, candidate: &CandidateId) -> Self {
        Self {
            root: state_root
                .join("candidates")
                .join(hex(candidate.as_bytes())),
        }
    }

    pub(crate) fn staging(state_root: &Path, candidate: &CandidateId) -> Self {
        Self {
            root: state_root
                .join("candidates")
                .join(format!(".migrate-{}", hex(candidate.as_bytes()))),
        }
    }

    /// Returns the candidate root supplied to per-record stores.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn candidates_root(&self) -> Result<&Path, std::io::Error> {
        self.root
            .parent()
            .ok_or_else(|| std::io::ErrorKind::InvalidInput.into())
    }

    pub(crate) fn initialize(&self) -> Result<(), std::io::Error> {
        let candidates_root = self.candidates_root()?.to_path_buf();
        for directory in [
            candidates_root,
            self.root.clone(),
            self.root.join("profiles"),
            self.root.join("trust"),
            self.root.join("records"),
            self.root.join("request-ids"),
            self.root.join("lease-chains"),
            self.root.join("run"),
        ] {
            fs::create_dir_all(&directory)?;
            fs::set_permissions(
                directory,
                fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )?;
        }
        Ok(())
    }

    pub(crate) fn transcript(&self) -> PathBuf {
        self.root.join("donor-transcript-v1")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        },
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::CandidateLayout;
    use crate::{
        candidate::{PairingAdmission, PairingCatalog},
        provisioning_io::FileStateStore,
    };

    #[test]
    fn each_candidate_root_is_disjoint_and_derived_only_from_the_candidate_id()
    -> Result<(), Box<dyn std::error::Error>> {
        // Given
        let root = Path::new("/state");
        let mut catalog = PairingCatalog::empty();
        catalog.admit(admission(1))?;
        catalog.admit(admission(2))?;
        let candidate_a = catalog.lookup([1; 32], [0x40; 32], 9)?;
        let candidate_b = catalog.lookup([2; 32], [0x40; 32], 9)?;

        // When
        let layout_a = CandidateLayout::new(root, candidate_a.candidate());
        let layout_b = CandidateLayout::new(root, candidate_b.candidate());
        let store_a = FileStateStore::new(layout_a.root());
        let store_b = FileStateStore::new(layout_b.root());

        // Then
        assert_ne!(layout_a.root(), layout_b.root());
        assert!(!layout_a.root().starts_with(layout_b.root()));
        assert!(!layout_b.root().starts_with(layout_a.root()));
        assert_eq!(
            layout_a.root().parent(),
            Some(root.join("candidates").as_path())
        );
        assert_eq!(
            layout_b.root().parent(),
            Some(root.join("candidates").as_path())
        );
        assert_ne!(
            store_a.record_path(b"paired-activation-v1")?,
            store_b.record_path(b"paired-activation-v1")?
        );
        Ok(())
    }

    const fn admission(value: u8) -> PairingAdmission {
        PairingAdmission {
            peer_spki_hash: [value; 32],
            profile_id_hash: [0x40; 32],
            profile_epoch: 9,
            candidate_identity_hash: [value; 32],
        }
    }
}
