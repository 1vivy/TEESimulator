use rka_state::{StateError, StateStore};
use std::path::Path;
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::{AuthenticatedCandidateContext, codec};
use crate::provisioning_io::FileStateStore;

/// Raw trusted pairing coordinates presented for catalog admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PairingAdmission {
    /// Verified candidate transport SPKI hash.
    pub peer_spki_hash: [u8; 32],
    /// Selected direct-profile identifier hash.
    pub profile_id_hash: [u8; 32],
    /// Selected direct-profile epoch.
    pub profile_epoch: u64,
    /// Existing self-authenticating candidate identity hash.
    pub candidate_identity_hash: [u8; 32],
}

/// Opaque proof that only catalog lookup can mint.
#[derive(Clone, Copy, Debug)]
pub struct CatalogAdmission(());

/// Pairing catalog admission and lookup failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CatalogError {
    /// A transport pin already names another admitted candidate.
    #[error("candidate transport pin is already admitted")]
    DuplicatePin,
    /// A candidate identity already has another admitted transport pin.
    #[error("candidate identity is already admitted")]
    DuplicateCandidate,
    /// The donor-wide candidate limit is exhausted.
    #[error("candidate catalog capacity is exhausted")]
    Capacity,
    /// No entry matched all authenticated profile coordinates.
    #[error("candidate catalog lookup failed")]
    NotFound,
    /// Catalog storage failed.
    #[error("candidate catalog storage failed")]
    Storage,
    /// Persisted catalog bytes were malformed.
    #[error("candidate catalog record is corrupt")]
    Corrupt,
}

/// Bounded donor-wide mapping from authenticated profiles to candidates.
#[derive(Debug)]
pub struct PairingCatalog {
    entries: Vec<PairingAdmission>,
}

impl PairingCatalog {
    /// Creates an empty catalog before trusted pairing admission.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Admits one unique transport pin and candidate identity.
    pub fn admit(&mut self, admission: PairingAdmission) -> Result<(), CatalogError> {
        if self
            .entries
            .iter()
            .any(|entry| bool::from(entry.peer_spki_hash.ct_eq(&admission.peer_spki_hash)))
        {
            return Err(CatalogError::DuplicatePin);
        }
        if self.entries.iter().any(|entry| {
            bool::from(
                entry
                    .candidate_identity_hash
                    .ct_eq(&admission.candidate_identity_hash),
            )
        }) {
            return Err(CatalogError::DuplicateCandidate);
        }
        if self.entries.len() >= codec::MAX_ENTRIES {
            return Err(CatalogError::Capacity);
        }
        self.entries.push(admission);
        Ok(())
    }

    /// Resolves one candidate from verified pin and selected-profile coordinates.
    #[allow(
        clippy::too_many_arguments,
        reason = "the required lookup seam takes pin, profile identifier, and profile epoch"
    )]
    pub fn lookup(
        &self,
        peer_spki_hash: [u8; 32],
        profile_id_hash: [u8; 32],
        profile_epoch: u64,
    ) -> Result<AuthenticatedCandidateContext, CatalogError> {
        let mut matched = None;
        for entry in &self.entries {
            let pin_matches = bool::from(entry.peer_spki_hash.ct_eq(&peer_spki_hash));
            if pin_matches
                && entry.profile_id_hash == profile_id_hash
                && entry.profile_epoch == profile_epoch
            {
                matched = Some(*entry);
            }
        }
        matched
            .map(|entry| AuthenticatedCandidateContext::admitted(CatalogAdmission(()), entry))
            .ok_or(CatalogError::NotFound)
    }

    /// Loads the canonical catalog from the root-owned state store.
    pub fn load(state_root: &Path) -> Result<Self, CatalogError> {
        let store = FileStateStore::new(state_root);
        let mut encoded = [0_u8; codec::MAX_ENCODED_BYTES];
        let length = store
            .read(codec::RECORD_KEY, &mut encoded)
            .map_err(CatalogError::from)?;
        let entries = codec::decode(encoded.get(..length).ok_or(CatalogError::Corrupt)?)?;
        let mut catalog = Self::empty();
        for entry in entries {
            catalog.admit(entry).map_err(|error| match error {
                CatalogError::DuplicatePin
                | CatalogError::DuplicateCandidate
                | CatalogError::Capacity => CatalogError::Corrupt,
                CatalogError::NotFound | CatalogError::Storage | CatalogError::Corrupt => error,
            })?;
        }
        Ok(catalog)
    }

    /// Atomically persists the canonical catalog under the state root.
    pub fn persist(&self, state_root: &Path) -> Result<(), CatalogError> {
        let store = FileStateStore::new(state_root);
        let encoded = codec::encode(&self.entries)?;
        store
            .replace(codec::RECORD_KEY, &encoded)
            .map_err(CatalogError::from)
    }
}

impl From<StateError> for CatalogError {
    fn from(error: StateError) -> Self {
        match error {
            StateError::Corrupt | StateError::RecordTooLarge { .. } | StateError::Capacity => {
                Self::Corrupt
            }
            StateError::Replay | StateError::TimeRegression => Self::Corrupt,
            _ => Self::Storage,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{CatalogError, PairingAdmission, PairingCatalog};

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempCatalog(PathBuf);

    impl TempCatalog {
        fn new(label: &str) -> Result<Self, std::io::Error> {
            let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("rka-catalog-{label}-{}-{id}", std::process::id()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TempCatalog {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const fn admission(value: u8) -> PairingAdmission {
        PairingAdmission {
            peer_spki_hash: [value; 32],
            profile_id_hash: [0x40; 32],
            profile_epoch: 9,
            candidate_identity_hash: [value.saturating_add(0x40); 32],
        }
    }

    #[test]
    fn duplicate_peer_pin_is_rejected_at_admission() -> Result<(), CatalogError> {
        // Given
        let mut catalog = PairingCatalog::empty();
        catalog.admit(admission(1))?;
        let duplicate_pin = PairingAdmission {
            peer_spki_hash: [1; 32],
            profile_id_hash: [0x41; 32],
            profile_epoch: 10,
            candidate_identity_hash: [0x42; 32],
        };

        // When
        let result = catalog.admit(duplicate_pin);

        // Then
        assert_eq!(result, Err(CatalogError::DuplicatePin));
        Ok(())
    }

    #[test]
    fn lookup_by_verified_pin_and_profile_returns_the_paired_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        // Given
        let state = TempCatalog::new("lookup")?;
        let mut catalog = PairingCatalog::empty();
        catalog.admit(admission(2))?;
        catalog.persist(&state.0)?;
        let reopened = PairingCatalog::load(&state.0)?;

        // When
        let authenticated = reopened.lookup([2; 32], [0x40; 32], 9)?;

        // Then
        assert_eq!(authenticated.candidate().as_bytes(), &[0x42; 32]);
        Ok(())
    }

    #[test]
    fn catalog_rejects_the_thirty_third_entry() -> Result<(), CatalogError> {
        // Given
        let mut catalog = PairingCatalog::empty();
        for value in 0..32 {
            catalog.admit(admission(value))?;
        }

        // When
        let result = catalog.admit(admission(32));

        // Then
        assert_eq!(result, Err(CatalogError::Capacity));
        Ok(())
    }
}
