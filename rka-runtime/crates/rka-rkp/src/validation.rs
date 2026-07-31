use crate::{
    PreparedCertificateRequest, RootBundle, StatusSnapshot, csr::hash, parse_signed_certificates,
};
use thiserror::Error;
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, time::ASN1Time};

/// Expected generated-key identity used to bind and reorder returned leaf certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedKey {
    handle: [u8; 32],
    spki_hash: [u8; 32],
}

impl ExpectedKey {
    /// Creates an expected key from its opaque handle and leaf SPKI SHA-256 digest.
    #[must_use]
    pub const fn new(handle: [u8; 32], spki_hash: [u8; 32]) -> Self {
        Self { handle, spki_hash }
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
    /// `BasicConstraints` or `KeyUsage` did not match the certificate role.
    #[error("certificate usage or type is invalid")]
    CertificateType,
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
            leaf_spki_hash: found_chain.0,
            chain_hash: found_chain.1,
            certificate_count: found_chain.2,
        });
    }
    Ok(ValidatedResponse { chains: ordered })
}

fn parse_chain(bytes: &[u8]) -> Result<Vec<X509Certificate<'_>>, ValidationError> {
    let mut remaining = bytes;
    let mut certificates = Vec::new();
    while !remaining.is_empty() {
        let (rest, certificate) =
            parse_x509_certificate(remaining).map_err(|_| ValidationError::Der)?;
        if rest.len() == remaining.len() {
            return Err(ValidationError::Der);
        }
        certificates.push(certificate);
        remaining = rest;
    }
    if certificates.len() < 2 {
        return Err(ValidationError::Der);
    }
    Ok(certificates)
}

#[allow(
    clippy::too_many_arguments,
    reason = "chain validation binds DER to epoch, time, roots, and status"
)]
fn validate_chain(
    certificates: &[X509Certificate<'_>],
    encoded: &[u8],
    epoch: u64,
    now: u64,
    roots: &RootBundle,
    status: &StatusSnapshot,
) -> Result<(), ValidationError> {
    let time = ASN1Time::from_timestamp(i64::try_from(now).map_err(|_| ValidationError::Validity)?)
        .map_err(|_| ValidationError::Validity)?;
    for (index, certificate) in certificates.iter().enumerate() {
        if !certificate.validity().is_valid_at(time) {
            return Err(ValidationError::Validity);
        }
        status.require_good(now, &certificate.raw_serial_as_string())?;
        let is_leaf = index == 0;
        let ca = certificate
            .basic_constraints()
            .map_err(|_| ValidationError::CertificateType)?
            .is_some_and(|extension| extension.value.ca);
        let usage = certificate
            .key_usage()
            .map_err(|_| ValidationError::CertificateType)?;
        let valid_usage = usage.as_ref().is_some_and(|extension| {
            if is_leaf {
                extension.value.digital_signature()
            } else {
                extension.value.key_cert_sign()
            }
        });
        if ca == is_leaf || !valid_usage {
            return Err(ValidationError::CertificateType);
        }
        if let Some(issuer) = certificates.get(index.saturating_add(1)) {
            certificate
                .verify_signature(Some(issuer.public_key()))
                .map_err(|_| ValidationError::Signature)?;
        }
    }
    let root = certificates.last().ok_or(ValidationError::Der)?;
    root.verify_signature(Some(root.public_key()))
        .map_err(|_| ValidationError::Signature)?;
    let root_start = encoded
        .len()
        .checked_sub(root.as_ref().len())
        .ok_or(ValidationError::Der)?;
    roots.admits(
        epoch,
        encoded.get(root_start..).ok_or(ValidationError::Der)?,
    )
}
