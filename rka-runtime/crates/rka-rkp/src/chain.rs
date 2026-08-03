use x509_parser::{certificate::X509Certificate, parse_x509_certificate, time::ASN1Time};

use crate::{RootBundle, StatusSnapshot, ValidationError, parse_signed_certificates};

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling validation module consumes the private chain implementation"
)]
pub(crate) fn parse_chain(bytes: &[u8]) -> Result<Vec<X509Certificate<'_>>, ValidationError> {
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
    clippy::redundant_pub_crate,
    clippy::too_many_arguments,
    reason = "sibling validation binds DER, time, epoch, status, and roots"
)]
pub(crate) fn validate_chain(
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
        status.require_good(now, &canonical_serial(certificate)?)?;
        let is_leaf = index == 0;
        let basic_constraints_error = if is_leaf {
            ValidationError::AttestationBasicConstraints
        } else {
            ValidationError::AuthorityBasicConstraints
        };
        let key_usage_error = if is_leaf {
            ValidationError::AttestationKeyUsage
        } else {
            ValidationError::AuthorityKeyUsage
        };
        let extended_key_usage_error = if is_leaf {
            ValidationError::AttestationExtendedKeyUsage
        } else {
            ValidationError::AuthorityExtendedKeyUsage
        };
        let ca = certificate
            .basic_constraints()
            .map_err(|_| basic_constraints_error)?
            .is_some_and(|extension| extension.value.ca);
        if !ca {
            return Err(basic_constraints_error);
        }
        let usage = certificate.key_usage().map_err(|_| key_usage_error)?;
        let valid_usage = usage.as_ref().is_some_and(|extension| {
            if is_leaf {
                extension.value.digital_signature() && extension.value.key_cert_sign()
            } else {
                extension.value.key_cert_sign()
            }
        });
        if !valid_usage {
            return Err(key_usage_error);
        }
        if certificate
            .extended_key_usage()
            .map_err(|_| extended_key_usage_error)?
            .is_some()
        {
            return Err(extended_key_usage_error);
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

/// Extracts every returned certificate serial before the status lookup.
pub fn returned_serials(
    server_response: &[u8],
    expected_count: usize,
) -> Result<Vec<String>, ValidationError> {
    let chains = parse_signed_certificates(server_response, expected_count)?;
    let mut serials = Vec::new();
    for encoded in &chains {
        for certificate in parse_chain(encoded)? {
            let serial = canonical_serial(&certificate)?;
            if !serials.contains(&serial) {
                serials.push(serial);
            }
        }
    }
    Ok(serials)
}

fn canonical_serial(certificate: &X509Certificate<'_>) -> Result<String, ValidationError> {
    let raw = certificate.raw_serial();
    let mut encoded = String::with_capacity(raw.len().saturating_mul(2));
    for byte in raw {
        let high = LOWER_HEX
            .get(usize::from(byte >> 4))
            .copied()
            .ok_or(ValidationError::Status)?;
        let low = LOWER_HEX
            .get(usize::from(byte & 0x0f))
            .copied()
            .ok_or(ValidationError::Status)?;
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    let serial = encoded.trim_start_matches('0');
    if serial.is_empty() {
        return Err(ValidationError::Status);
    }
    Ok(serial.to_owned())
}
