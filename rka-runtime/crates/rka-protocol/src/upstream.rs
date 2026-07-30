//! Standard upstream RKP byte-boundary guard.

use crate::ProtocolError;

pub fn validate_upstream_rkp_bytes(
    standard_bytes: &[u8],
    envelope_bytes: &[u8],
) -> Result<(), ProtocolError> {
    crate::validate_deterministic_cbor(standard_bytes)?;
    if envelope_bytes.is_empty() {
        return Ok(());
    }
    if standard_bytes
        .windows(envelope_bytes.len())
        .any(|window| window == envelope_bytes)
    {
        return Err(ProtocolError::ForbiddenMaterial);
    }
    Ok(())
}
