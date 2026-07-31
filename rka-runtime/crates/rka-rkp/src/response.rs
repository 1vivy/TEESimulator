use ciborium::value::Value;
use std::io::Cursor;

use crate::ValidationError;

/// Decodes Android's `[shared, unique[]]` certificate response into complete chains.
pub fn parse_signed_certificates(
    body: &[u8],
    expected: usize,
) -> Result<Vec<Vec<u8>>, ValidationError> {
    if body.is_empty() || body.len() > crate::MAX_PROVISIONING_BYTES || expected == 0 {
        return Err(ValidationError::Response);
    }
    let mut cursor = Cursor::new(body);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| ValidationError::Response)?;
    if usize::try_from(cursor.position()).map_err(|_| ValidationError::Response)? != body.len() {
        return Err(ValidationError::Response);
    }
    let Value::Array(fields) = value else {
        return Err(ValidationError::Response);
    };
    let [Value::Bytes(shared), Value::Array(unique)] = fields.as_slice() else {
        return Err(ValidationError::Response);
    };
    if unique.len() != expected {
        return Err(ValidationError::Count);
    }
    let mut chains = Vec::with_capacity(unique.len());
    for item in unique {
        let Value::Bytes(prefix) = item else {
            return Err(ValidationError::Response);
        };
        if prefix.is_empty() || shared.is_empty() {
            return Err(ValidationError::Response);
        }
        let mut chain = Vec::with_capacity(prefix.len().saturating_add(shared.len()));
        chain.extend_from_slice(prefix);
        chain.extend_from_slice(shared);
        if chains.iter().any(|prior| prior == &chain) {
            return Err(ValidationError::DuplicateChain);
        }
        chains.push(chain);
    }
    Ok(chains)
}
