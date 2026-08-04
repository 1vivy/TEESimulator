use super::{CatalogError, PairingAdmission};

pub(super) const MAX_ENTRIES: usize = 32;
pub(super) const RECORD_KEY: &[u8] = b"candidate-catalog-v2";
const MAGIC: &[u8; 5] = b"RKCC\x02";
const HEADER_BYTES: usize = 6;
const ENTRY_BYTES: usize = 104;
pub(super) const MAX_ENCODED_BYTES: usize = HEADER_BYTES + MAX_ENTRIES * ENTRY_BYTES;

pub(super) fn encode(entries: &[PairingAdmission]) -> Result<Vec<u8>, CatalogError> {
    let count = u8::try_from(entries.len()).map_err(|_| CatalogError::Capacity)?;
    if entries.len() > MAX_ENTRIES {
        return Err(CatalogError::Capacity);
    }
    let mut encoded =
        Vec::with_capacity(HEADER_BYTES.saturating_add(entries.len().saturating_mul(ENTRY_BYTES)));
    encoded.extend_from_slice(MAGIC);
    encoded.push(count);
    for entry in entries {
        encoded.extend_from_slice(&entry.peer_spki_hash);
        encoded.extend_from_slice(&entry.profile_id_hash);
        encoded.extend_from_slice(&entry.profile_epoch.to_be_bytes());
        encoded.extend_from_slice(&entry.candidate_identity_hash);
    }
    Ok(encoded)
}

pub(super) fn decode(encoded: &[u8]) -> Result<Vec<PairingAdmission>, CatalogError> {
    if encoded.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CatalogError::Corrupt);
    }
    let count = usize::from(*encoded.get(MAGIC.len()).ok_or(CatalogError::Corrupt)?);
    if count > MAX_ENTRIES
        || encoded.len() != HEADER_BYTES.saturating_add(count.saturating_mul(ENTRY_BYTES))
    {
        return Err(CatalogError::Corrupt);
    }
    let mut remaining = encoded.get(HEADER_BYTES..).ok_or(CatalogError::Corrupt)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let (peer_spki_hash, rest) = take_array(remaining)?;
        let (profile_id_hash, rest) = take_array(rest)?;
        let (profile_epoch, rest) = take_array(rest)?;
        let (candidate_identity_hash, rest) = take_array(rest)?;
        entries.push(PairingAdmission {
            peer_spki_hash,
            profile_id_hash,
            profile_epoch: u64::from_be_bytes(profile_epoch),
            candidate_identity_hash,
        });
        remaining = rest;
    }
    if !remaining.is_empty() {
        return Err(CatalogError::Corrupt);
    }
    Ok(entries)
}

fn take_array<const N: usize>(input: &[u8]) -> Result<([u8; N], &[u8]), CatalogError> {
    let (value, remaining) = input.split_at_checked(N).ok_or(CatalogError::Corrupt)?;
    let array = value.try_into().map_err(|_| CatalogError::Corrupt)?;
    Ok((array, remaining))
}
