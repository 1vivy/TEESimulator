use super::catalog::{CatalogAdmission, PairingAdmission};

/// Candidate identity admitted from the trusted pairing catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateId([u8; 32]);

impl CandidateId {
    /// Returns the existing candidate identity hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Candidate coordinates resolved from authenticated transport inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedCandidateContext {
    candidate: CandidateId,
    peer_spki_hash: [u8; 32],
    profile_id_hash: [u8; 32],
    profile_epoch: u64,
}

impl AuthenticatedCandidateContext {
    pub(crate) const fn admitted(_: CatalogAdmission, admission: PairingAdmission) -> Self {
        Self {
            candidate: CandidateId(admission.candidate_identity_hash),
            peer_spki_hash: admission.peer_spki_hash,
            profile_id_hash: admission.profile_id_hash,
            profile_epoch: admission.profile_epoch,
        }
    }

    /// Returns the catalog-authenticated candidate identity.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateId {
        &self.candidate
    }

    /// Returns the verified peer SPKI hash.
    #[must_use]
    pub const fn peer_spki_hash(&self) -> &[u8; 32] {
        &self.peer_spki_hash
    }

    /// Returns the selected profile identifier hash.
    #[must_use]
    pub const fn profile_id_hash(&self) -> &[u8; 32] {
        &self.profile_id_hash
    }

    /// Returns the selected profile epoch.
    #[must_use]
    pub const fn profile_epoch(&self) -> u64 {
        self.profile_epoch
    }
}

#[cfg(test)]
mod tests {
    use crate::candidate::{PairingAdmission, PairingCatalog};

    #[test]
    fn candidate_id_has_no_public_constructor_from_raw_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        // Given
        let mut catalog = PairingCatalog::empty();
        catalog.admit(PairingAdmission {
            peer_spki_hash: [0x11; 32],
            profile_id_hash: [0x22; 32],
            profile_epoch: 7,
            candidate_identity_hash: [0x33; 32],
        })?;

        // When
        let first = catalog.lookup([0x11; 32], [0x22; 32], 7)?;
        let second = catalog.lookup([0x11; 32], [0x22; 32], 7)?;

        // Then
        assert_eq!(first.candidate(), second.candidate());
        let source = include_str!("id.rs");
        assert!(!source.contains(concat!("pub fn ", "new")));
        assert!(!source.contains(concat!("impl From<", "[u8; 32]> for CandidateId")));
        assert!(!source.contains(concat!("derive(", "Default)")));
        Ok(())
    }
}
