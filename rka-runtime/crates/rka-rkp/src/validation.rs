use crate::{
    PreparedCertificateRequest, RootBundle, StatusSnapshot,
    chain::{parse_chain, validate_chain},
    csr::hash,
    parse_signed_certificates,
};
use thiserror::Error;

/// Expected generated-key identity used to bind and reorder returned leaf certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedKey {
    handle: [u8; 32],
    public_key_hash: [u8; 32],
    spki_hash: [u8; 32],
}

impl ExpectedKey {
    /// Creates an expected key from its opaque handle and leaf SPKI SHA-256 digest.
    #[must_use]
    pub const fn new(handle: [u8; 32], spki_hash: [u8; 32]) -> Self {
        Self {
            handle,
            public_key_hash: spki_hash,
            spki_hash,
        }
    }

    /// Creates an expected key with distinct MACed-public and SPKI hashes.
    #[must_use]
    pub const fn with_public_hash(
        handle: [u8; 32],
        public_key_hash: [u8; 32],
        spki_hash: [u8; 32],
    ) -> Self {
        Self {
            handle,
            public_key_hash,
            spki_hash,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(handle: [u8; 32], spki_hash: [u8; 32]) -> Self {
        Self::new(handle, spki_hash)
    }
}

/// Replay and profile coordinates bound to one provisioning response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseContext {
    hal_csr_hash: [u8; 32],
    expected_request_id: String,
    observed_request_id: String,
    expected_challenge_hash: [u8; 32],
    observed_challenge_hash: [u8; 32],
    profile_epoch: u64,
    now_unix_seconds: u64,
}

impl ResponseContext {
    /// Creates a closed response-validation context.
    #[allow(
        clippy::too_many_arguments,
        reason = "closed response binding carries independent anti-replay coordinates"
    )]
    #[must_use]
    pub fn new(
        hal_csr_hash: [u8; 32],
        expected_request_id: &str,
        observed_request_id: &str,
        expected_challenge_hash: [u8; 32],
        observed_challenge_hash: [u8; 32],
        profile_epoch: u64,
        now_unix_seconds: u64,
    ) -> Self {
        Self {
            hal_csr_hash,
            expected_request_id: expected_request_id.to_owned(),
            observed_request_id: observed_request_id.to_owned(),
            expected_challenge_hash,
            observed_challenge_hash,
            profile_epoch,
            now_unix_seconds,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn for_test(hal_csr_hash: [u8; 32], request_id: &str, profile_epoch: u64) -> Self {
        Self::new(
            hal_csr_hash,
            request_id,
            request_id,
            [4; 32],
            [4; 32],
            profile_epoch,
            7,
        )
    }
}

/// Validated metadata for one complete returned certificate chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValidatedChain {
    /// Original generated-key order.
    pub order: u8,
    /// Opaque generated-key handle.
    pub handle: [u8; 32],
    /// SHA-256 digest of the `MACed` public key.
    pub public_key_hash: [u8; 32],
    /// SHA-256 digest of the leaf `SubjectPublicKeyInfo`.
    pub leaf_spki_hash: [u8; 32],
    /// SHA-256 digest of the exact concatenated DER chain.
    pub chain_hash: [u8; 32],
    /// Number of certificates in the complete chain.
    pub certificate_count: u8,
}

/// Fully validated chains reordered to their generated-key order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedResponse {
    chains: Vec<ValidatedChain>,
}

impl ValidatedResponse {
    /// Returns validated chains in generated-key order.
    #[must_use]
    pub fn chains(&self) -> &[ValidatedChain] {
        &self.chains
    }
}

/// Fail-closed request, response, trust, and certificate validation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The HAL CSR was not one complete CBOR array.
    #[error("invalid CBOR")]
    Cbor,
    /// The server response did not match the required CBOR shape.
    #[error("invalid server response")]
    Response,
    /// Returned or expected item counts did not match.
    #[error("certificate count mismatch")]
    Count,
    /// Two returned complete chains were byte-identical.
    #[error("duplicate certificate chain")]
    DuplicateChain,
    /// The transmitted upload body or HAL CSR binding changed.
    #[error("CSR binding mismatch")]
    CsrMutation,
    /// The observed request identifier did not match.
    #[error("request identifier mismatch")]
    RequestId,
    /// The observed challenge digest did not match.
    #[error("challenge mismatch")]
    Challenge,
    /// Generated handles or SPKI hashes were duplicated.
    #[error("duplicate SPKI")]
    DuplicateSpki,
    /// Returned leaf SPKIs did not match expected keys one-to-one.
    #[error("missing or extra SPKI")]
    Spki,
    /// A concatenated certificate chain was not complete DER.
    #[error("invalid DER chain")]
    Der,
    /// A certificate signature was invalid.
    #[error("invalid certificate signature")]
    Signature,
    /// A certificate was outside its validity interval.
    #[error("certificate is outside its validity window")]
    Validity,
    /// The issued attestation-signing certificate was not a certificate authority.
    #[error("attestation certificate basic constraints are invalid")]
    AttestationBasicConstraints,
    /// The issued attestation-signing certificate lacked certificate-signing usage.
    #[error("attestation certificate key usage is invalid")]
    AttestationKeyUsage,
    /// The issued attestation-signing certificate declared an extended usage.
    #[error("attestation certificate extended key usage is invalid")]
    AttestationExtendedKeyUsage,
    /// An intermediate or root certificate was not a certificate authority.
    #[error("authority certificate basic constraints are invalid")]
    AuthorityBasicConstraints,
    /// An intermediate or root certificate lacked certificate-signing usage.
    #[error("authority certificate key usage is invalid")]
    AuthorityKeyUsage,
    /// An intermediate or root certificate declared an extended usage.
    #[error("authority certificate extended key usage is invalid")]
    AuthorityExtendedKeyUsage,
    /// The terminal root was not pinned.
    #[error("untrusted attestation root")]
    Root,
    /// The trust profile epoch did not match.
    #[error("profile epoch mismatch")]
    Epoch,
    /// Status metadata or cache policy was malformed.
    #[error("certificate status is unavailable")]
    Status,
    /// Status metadata was expired or not yet valid.
    #[error("certificate status is stale")]
    StatusStale,
    /// Status omitted a certificate in the returned chain.
    #[error("certificate status is incomplete")]
    StatusIncomplete,
    /// Status marked a certificate as revoked.
    #[error("certificate is revoked")]
    Revoked,
    /// A root-bundle rotation was not authorized.
    #[error("root rotation is unauthorized")]
    Rotation,
}

/// Validates a complete server response and quarantines every expected handle on failure.
#[allow(
    clippy::too_many_arguments,
    reason = "validation closes independent request, trust, status, and quarantine inputs"
)]
pub fn validate_response(
    prepared: &PreparedCertificateRequest,
    sent_body: &[u8],
    server_response: &[u8],
    expected: &[ExpectedKey],
    context: &ResponseContext,
    roots: &RootBundle,
    status: &StatusSnapshot,
    quarantine: &mut dyn FnMut([u8; 32]),
) -> Result<ValidatedResponse, ValidationError> {
    let result = validate(
        prepared,
        sent_body,
        server_response,
        expected,
        context,
        roots,
        status,
    );
    if result.is_err() {
        for key in expected {
            quarantine(key.handle);
        }
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal validation receives the same closed security coordinates"
)]
fn validate(
    prepared: &PreparedCertificateRequest,
    sent_body: &[u8],
    server_response: &[u8],
    expected: &[ExpectedKey],
    context: &ResponseContext,
    roots: &RootBundle,
    status: &StatusSnapshot,
) -> Result<ValidatedResponse, ValidationError> {
    if prepared.hal_csr_hash() != context.hal_csr_hash || prepared.body() != sent_body {
        return Err(ValidationError::CsrMutation);
    }
    if context.expected_request_id != context.observed_request_id {
        return Err(ValidationError::RequestId);
    }
    if context.expected_challenge_hash != context.observed_challenge_hash {
        return Err(ValidationError::Challenge);
    }
    if expected.is_empty() {
        return Err(ValidationError::Count);
    }
    for (index, key) in expected.iter().enumerate() {
        if expected
            .get(..index)
            .ok_or(ValidationError::Count)?
            .iter()
            .any(|prior| prior.spki_hash == key.spki_hash || prior.handle == key.handle)
        {
            return Err(ValidationError::DuplicateSpki);
        }
    }
    let encoded_chains = parse_signed_certificates(server_response, expected.len())?;
    let mut found = Vec::with_capacity(encoded_chains.len());
    for chain in &encoded_chains {
        let certificates = parse_chain(chain)?;
        validate_chain(
            &certificates,
            chain,
            context.profile_epoch,
            context.now_unix_seconds,
            roots,
            status,
        )?;
        let leaf_hash = hash(
            certificates
                .first()
                .ok_or(ValidationError::Der)?
                .public_key()
                .raw,
        );
        if found
            .iter()
            .any(|item: &([u8; 32], [u8; 32], u8)| item.0 == leaf_hash)
        {
            return Err(ValidationError::DuplicateSpki);
        }
        let count = u8::try_from(certificates.len()).map_err(|_| ValidationError::Count)?;
        found.push((leaf_hash, hash(chain), count));
    }
    let mut ordered = Vec::with_capacity(expected.len());
    for (order, key) in expected.iter().enumerate() {
        let matches = found
            .iter()
            .filter(|(spki, _, _)| *spki == key.spki_hash)
            .collect::<Vec<_>>();
        let [found_chain] = matches.as_slice() else {
            return Err(ValidationError::Spki);
        };
        ordered.push(ValidatedChain {
            order: u8::try_from(order).map_err(|_| ValidationError::Count)?,
            handle: key.handle,
            public_key_hash: key.public_key_hash,
            leaf_spki_hash: found_chain.0,
            chain_hash: found_chain.1,
            certificate_count: found_chain.2,
        });
    }
    Ok(ValidatedResponse { chains: ordered })
}
