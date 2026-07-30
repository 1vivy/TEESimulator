//! Module-only semi-unique RKP envelope.

use crate::{MAX_RKP_BATCH, MAX_USES, ProtocolError, TTL_SECONDS, cbor::CborReader};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Envelope<'a> {
    pub candidate_identity_hash: [u8; 32],
    pub aaid_hash: [u8; 32],
    pub profile_epoch: u64,
    pub candidate_nonce: [u8; 32],
    pub donor_nonce: [u8; 32],
    pub donor_irpc_identity_hash: [u8; 32],
    pub ordered_rkp_public_hashes: Option<Vec<[u8; 32]>>,
    pub hal_csr_hash: Option<[u8; 32]>,
    pub server_body_hash: Option<[u8; 32]>,
    pub server_challenge_hash: Option<[u8; 32]>,
    pub server_response_hash: Option<[u8; 32]>,
    pub validated_chain_set_hash: Option<[u8; 32]>,
    pub donor_monotonic_start_ms: u64,
    pub successful_finish_count: u8,
    marker: core::marker::PhantomData<&'a [u8]>,
}

pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope<'_>, ProtocolError> {
    crate::validate_deterministic_cbor(bytes)?;
    let mut reader = CborReader::new(bytes);
    let count = reader.map()?;
    if !(11..=17).contains(&count) {
        return Err(ProtocolError::MissingField);
    }
    expect_unsigned(&mut reader, 0, 1)?;
    expect_key(&mut reader, 1)?;
    let candidate_identity_hash = fixed(reader.bytes()?)?;
    expect_key(&mut reader, 2)?;
    let aaid_hash = fixed(reader.bytes()?)?;
    expect_key(&mut reader, 3)?;
    let profile_epoch = reader.unsigned()?;
    expect_key(&mut reader, 4)?;
    let candidate_nonce = fixed(reader.bytes()?)?;
    expect_key(&mut reader, 5)?;
    let donor_nonce = fixed(reader.bytes()?)?;
    expect_key(&mut reader, 6)?;
    let donor_irpc_identity_hash = fixed(reader.bytes()?)?;

    let optional_count = count.saturating_sub(11);
    let mut ordered_rkp_public_hashes = None;
    let mut hashes: [Option<[u8; 32]>; 5] = [None; 5];
    if optional_count > 0 {
        expect_key(&mut reader, 7)?;
        ordered_rkp_public_hashes = Some(decode_hashes(&mut reader)?);
    }
    for index in 0..optional_count.saturating_sub(1) {
        let key = 8_u64.saturating_add(u64::try_from(index).map_or(u64::MAX, |value| value));
        expect_key(&mut reader, key)?;
        let value = fixed(reader.bytes()?)?;
        if let Some(slot) = hashes.get_mut(index) {
            *slot = Some(value);
        }
    }
    expect_key(&mut reader, 13)?;
    let donor_monotonic_start_ms = reader.unsigned()?;
    expect_unsigned(&mut reader, 14, TTL_SECONDS)?;
    expect_unsigned(&mut reader, 15, MAX_USES)?;
    expect_key(&mut reader, 16)?;
    let successful_finish_count =
        u8::try_from(reader.unsigned()?).map_err(|_| ProtocolError::UnsupportedValue)?;
    if successful_finish_count > 1 || !reader.is_complete() {
        return Err(ProtocolError::UnsupportedValue);
    }
    Ok(Envelope {
        candidate_identity_hash,
        aaid_hash,
        profile_epoch,
        candidate_nonce,
        donor_nonce,
        donor_irpc_identity_hash,
        ordered_rkp_public_hashes,
        hal_csr_hash: value(&hashes, 0),
        server_body_hash: value(&hashes, 1),
        server_challenge_hash: value(&hashes, 2),
        server_response_hash: value(&hashes, 3),
        validated_chain_set_hash: value(&hashes, 4),
        donor_monotonic_start_ms,
        successful_finish_count,
        marker: core::marker::PhantomData,
    })
}

pub fn decode_envelope_reader<'a>(
    reader: &mut CborReader<'a>,
) -> Result<Envelope<'a>, ProtocolError> {
    let start = reader.position();
    reader.skip_item()?;
    decode_envelope(reader.slice_from(start)?)
}

fn decode_hashes(reader: &mut CborReader<'_>) -> Result<Vec<[u8; 32]>, ProtocolError> {
    let count = reader.array()?;
    if count == 0 || count > MAX_RKP_BATCH {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(fixed(reader.bytes()?)?);
    }
    Ok(hashes)
}

fn value(values: &[Option<[u8; 32]>], index: usize) -> Option<[u8; 32]> {
    values.get(index).copied().flatten()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes
        .try_into()
        .map_err(|_| ProtocolError::LengthOutOfRange)
}

fn expect_key(reader: &mut CborReader<'_>, expected: u64) -> Result<(), ProtocolError> {
    if reader.unsigned()? == expected {
        Ok(())
    } else {
        Err(ProtocolError::UnknownField)
    }
}

fn expect_unsigned(
    reader: &mut CborReader<'_>,
    key: u64,
    expected: u64,
) -> Result<(), ProtocolError> {
    expect_key(reader, key)?;
    if reader.unsigned()? == expected {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedValue)
    }
}
