use crate::ValidationError;
use crate::csr::hash;
use ring::signature::{ED25519, UnparsedPublicKey};

/// SHA-256 pins for Google's two published remote-provisioning roots.
pub const GOOGLE_ROOT_HASHES: [[u8; 32]; 2] = [
    [
        0xce, 0xdb, 0x1c, 0xb6, 0xdc, 0x89, 0x6a, 0xe5, 0xec, 0x79, 0x73, 0x48, 0xbc, 0xe9, 0x28,
        0x67, 0x53, 0xc2, 0xb3, 0x8e, 0xe7, 0x1c, 0xe0, 0xfb, 0xe3, 0x4a, 0x9a, 0x12, 0x48, 0x80,
        0x0d, 0xfc,
    ],
    [
        0x6d, 0x9d, 0xb4, 0xce, 0x6c, 0x5c, 0x0b, 0x29, 0x31, 0x66, 0xd0, 0x89, 0x86, 0xe0, 0x57,
        0x74, 0xa8, 0x77, 0x6c, 0xeb, 0x52, 0x5d, 0x9e, 0x43, 0x29, 0x52, 0x0d, 0xe1, 0x2b, 0xa4,
        0xbc, 0xc0,
    ],
];

/// Exact Google attestation roots published at `android.googleapis.com/attestation/root`.
pub const GOOGLE_ROOTS_DER: [&[u8]; 2] = [
    include_bytes!("../data/google-attestation-root-2022.der"),
    include_bytes!("../data/google-attestation-root-2025.der"),
];

const ROTATION_DOMAIN: &[u8] = b"TEESimulator-RS RKP root rotation v1\0";

/// Ed25519 authorization for a root rotation with no old/new pin overlap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRotationAuthorization {
    signature: [u8; 64],
}

impl RootRotationAuthorization {
    /// Creates an authorization carrying a signature from the bundle's trusted key.
    #[must_use]
    pub const fn new(signature: [u8; 64]) -> Self {
        Self { signature }
    }
}

/// Epoch-bound set of exact DER SHA-256 root pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootBundle {
    epoch: u64,
    pins: Vec<[u8; 32]>,
    roots: Vec<Vec<u8>>,
    bundle_hash: [u8; 32],
    rotation_public_key: Option<[u8; 32]>,
}

impl RootBundle {
    /// Creates the production bundle for a profile epoch.
    #[must_use]
    pub fn production(epoch: u64) -> Self {
        let roots = GOOGLE_ROOTS_DER
            .iter()
            .map(|root| root.to_vec())
            .collect::<Vec<_>>();
        let pins = roots.iter().map(|root| hash(root)).collect::<Vec<_>>();
        debug_assert_eq!(pins, GOOGLE_ROOT_HASHES);
        Self::new(epoch, pins, roots, None)
    }

    /// Creates a root bundle with a preconfigured Ed25519 rotation trust key.
    #[must_use]
    pub fn with_rotation_key(
        epoch: u64,
        pins: Vec<[u8; 32]>,
        rotation_public_key: [u8; 32],
    ) -> Self {
        Self::new(epoch, pins, Vec::new(), Some(rotation_public_key))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn for_test(epoch: u64, pins: Vec<[u8; 32]>) -> Self {
        Self::new(epoch, pins, Vec::new(), None)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "bundle construction keeps pins, exact roots, and rotation key distinct"
    )]
    fn new(
        epoch: u64,
        mut pins: Vec<[u8; 32]>,
        roots: Vec<Vec<u8>>,
        rotation_public_key: Option<[u8; 32]>,
    ) -> Self {
        pins.sort_unstable();
        pins.dedup();
        let bytes = pins.iter().flatten().copied().collect::<Vec<_>>();
        Self {
            epoch,
            pins,
            roots,
            bundle_hash: hash(&bytes),
            rotation_public_key,
        }
    }

    pub(crate) fn admits(&self, epoch: u64, root: &[u8]) -> Result<(), ValidationError> {
        if epoch != self.epoch {
            return Err(ValidationError::Epoch);
        }
        let admitted = if self.roots.is_empty() {
            self.pins.contains(&hash(root))
        } else {
            self.roots.iter().any(|candidate| candidate == root)
        };
        if !admitted {
            return Err(ValidationError::Root);
        }
        Ok(())
    }

    /// Returns the deterministic digest of the sorted root pins.
    #[must_use]
    pub const fn bundle_hash(&self) -> [u8; 32] {
        self.bundle_hash
    }

    /// Returns the profile epoch bound to this immutable bundle.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the domain-separated bytes that authorize a proposed rotation.
    pub fn rotation_message(
        &self,
        next_epoch: u64,
        pins: &[[u8; 32]],
    ) -> Result<Vec<u8>, ValidationError> {
        let next = Self::new(
            next_epoch,
            pins.to_vec(),
            Vec::new(),
            self.rotation_public_key,
        );
        if next_epoch != self.epoch.saturating_add(1) || next.bundle_hash == self.bundle_hash {
            return Err(ValidationError::Rotation);
        }
        let capacity = ROTATION_DOMAIN
            .len()
            .checked_add(72)
            .ok_or(ValidationError::Rotation)?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(ROTATION_DOMAIN);
        message.extend_from_slice(&self.bundle_hash);
        message.extend_from_slice(&next.bundle_hash);
        message.extend_from_slice(&next_epoch.to_be_bytes());
        Ok(message)
    }

    /// Advances one epoch, requiring overlap or a valid Ed25519 authorization.
    #[allow(
        clippy::too_many_arguments,
        reason = "rotation binds epoch, complete pin set, and optional authorization"
    )]
    pub fn rotate(
        &self,
        next_epoch: u64,
        pins: Vec<[u8; 32]>,
        authorization: Option<&RootRotationAuthorization>,
    ) -> Result<Self, ValidationError> {
        let next = Self::new(next_epoch, pins, Vec::new(), self.rotation_public_key);
        let message = self.rotation_message(next_epoch, &next.pins)?;
        let overlaps = next.pins.iter().any(|pin| self.pins.contains(pin));
        if !overlaps {
            let authorization = authorization.ok_or(ValidationError::Rotation)?;
            let public_key = self.rotation_public_key.ok_or(ValidationError::Rotation)?;
            UnparsedPublicKey::new(&ED25519, public_key)
                .verify(&message, &authorization.signature)
                .map_err(|_| ValidationError::Rotation)?;
        }
        Ok(next)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test setup must fail immediately if ephemeral Ed25519 generation fails"
)]
mod tests {
    use super::{RootBundle, RootRotationAuthorization};
    use crate::ValidationError;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    #[test]
    fn rotation_accepts_overlap_without_authorization() {
        let current = RootBundle::for_test(7, vec![[1; 32], [2; 32]]);

        let next = current.rotate(8, vec![[2; 32], [3; 32]], None).unwrap();

        assert_ne!(next.bundle_hash(), current.bundle_hash());
    }

    #[test]
    fn rotation_requires_valid_signature_without_overlap() {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let current = RootBundle::with_rotation_key(
            7,
            vec![[1; 32]],
            signer.public_key().as_ref().try_into().unwrap(),
        );
        let pins = vec![[2; 32]];
        let message = current.rotation_message(8, &pins).unwrap();
        let signature = signer.sign(&message);
        let authorization = RootRotationAuthorization::new(signature.as_ref().try_into().unwrap());

        assert!(
            current
                .rotate(8, pins.clone(), Some(&authorization))
                .is_ok()
        );
        assert_eq!(
            current.rotate(8, pins.clone(), None),
            Err(ValidationError::Rotation)
        );
        let bad = RootRotationAuthorization::new([0; 64]);
        assert_eq!(
            current.rotate(8, pins, Some(&bad)),
            Err(ValidationError::Rotation)
        );
    }

    #[test]
    fn rotation_rejects_epoch_skip_and_unchanged_bundle() {
        let current = RootBundle::for_test(7, vec![[1; 32]]);

        assert_eq!(
            current.rotate(9, vec![[1; 32], [2; 32]], None),
            Err(ValidationError::Rotation)
        );
        assert_eq!(
            current.rotate(8, vec![[1; 32]], None),
            Err(ValidationError::Rotation)
        );
    }
}
