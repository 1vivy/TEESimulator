use core::fmt;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, PKCS_ED25519,
    PublicKeyData, SerialNumber,
};
use rka_protocol::sha256;
use rka_state::{SensitiveStateStore, StateError};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_KEY: &[u8] = b"transport-identity-pkcs8";

/// Module-generated transport-only Ed25519 identity.
pub struct TransportIdentity {
    certificate: Vec<u8>,
    public_spki: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
}

impl TransportIdentity {
    /// Generates fixed-subject transport material and retains private bytes zeroized.
    pub fn generate(host: &str) -> Result<Self, IdentityError> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| IdentityError::Generate)?;
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|_| IdentityError::Host)?;
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, "TEESimulator RKA Transport");
        params.distinguished_name = subject;
        params.serial_number = Some(SerialNumber::from_slice(&[1]));
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|_| IdentityError::Generate)?;
        let public_spki = key_pair.subject_public_key_info();
        let private = Zeroizing::new(key_pair.serialize_der());
        Ok(Self {
            certificate: certificate.der().to_vec(),
            public_spki,
            private,
        })
    }

    /// Persists private state only through the explicit sensitive boundary.
    pub fn persist<S: SensitiveStateStore>(&self, store: &S) -> Result<(), IdentityError> {
        store
            .replace_sensitive(IDENTITY_KEY, &self.private)
            .map_err(IdentityError::State)
    }

    /// Returns the public certificate.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// Returns the exact transport SPKI hash.
    #[must_use]
    pub fn spki_hash(&self) -> [u8; 32] {
        sha256(&self.public_spki)
    }
}

impl fmt::Debug for TransportIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportIdentity")
            .field("private", &"[redacted]")
            .field("certificate", &"[public certificate]")
            .finish()
    }
}

/// Transport identity generation or persistence failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Host cannot be represented as a certificate SAN.
    #[error("transport identity host is invalid")]
    Host,
    /// Cryptographic generation failed.
    #[error("transport identity generation failed")]
    Generate,
    /// Protected persistence failed.
    #[error("transport identity persistence failed")]
    State(#[source] StateError),
}
