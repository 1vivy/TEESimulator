use ciborium::value::Value;
use ring::digest::{SHA256, digest};
use std::io::Cursor;

use crate::ValidationError;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Exact Android v3 upload body and hashes binding it to the HAL output.
pub struct PreparedCertificateRequest {
    hal_csr_hash: [u8; 32],
    server_body_hash: [u8; 32],
    body: Vec<u8>,
}

impl PreparedCertificateRequest {
    /// Returns the exact CBOR bytes that must be uploaded.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the SHA-256 digest of the unmodified HAL CSR bytes.
    #[must_use]
    pub const fn hal_csr_hash(&self) -> [u8; 32] {
        self.hal_csr_hash
    }

    /// Returns the SHA-256 digest of the assembled upload body.
    #[must_use]
    pub const fn server_body_hash(&self) -> [u8; 32] {
        self.server_body_hash
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(
        hal_csr_hash: [u8; 32],
        server_body_hash: [u8; 32],
        body: Vec<u8>,
    ) -> Self {
        Self {
            hal_csr_hash,
            server_body_hash,
            body,
        }
    }
}

/// Appends Android's unverified fingerprint map to a decoded v3 HAL CSR array.
///
/// Signature-covered byte strings inside the HAL response are preserved verbatim.
pub fn assemble_android_v3_body(
    hal_csr: &[u8],
    fingerprint: &str,
) -> Result<PreparedCertificateRequest, ValidationError> {
    if hal_csr.is_empty() || hal_csr.len() > crate::MAX_PROVISIONING_BYTES || fingerprint.is_empty()
    {
        return Err(ValidationError::Cbor);
    }
    let mut cursor = Cursor::new(hal_csr);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| ValidationError::Cbor)?;
    if usize::try_from(cursor.position()).map_err(|_| ValidationError::Cbor)? != hal_csr.len() {
        return Err(ValidationError::Cbor);
    }
    let Value::Array(mut outer) = value else {
        return Err(ValidationError::Cbor);
    };
    outer.push(Value::Map(vec![(
        Value::Text("fingerprint".to_owned()),
        Value::Text(fingerprint.to_owned()),
    )]));
    let mut body = Vec::new();
    ciborium::into_writer(&Value::Array(outer), &mut body).map_err(|_| ValidationError::Cbor)?;
    if body.len() > crate::MAX_PROVISIONING_BYTES {
        return Err(ValidationError::Cbor);
    }
    Ok(PreparedCertificateRequest {
        hal_csr_hash: hash(hal_csr),
        server_body_hash: hash(&body),
        body,
    })
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling trust and validation modules share this private-module helper"
)]
pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    value
}
