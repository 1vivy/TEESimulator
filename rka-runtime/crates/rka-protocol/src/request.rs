//! Exact foreground `KeyMint` request shape.

use crate::{
    MAX_ATTESTATION_CHALLENGE_BYTES, MAX_OPERATION_INPUT_BYTES, MIN_ATTESTATION_CHALLENGE_BYTES,
    ProtocolError, cbor::CborReader,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ForegroundRequest<'a> {
    pub attestation_challenge: &'a [u8],
    pub alias_handle: [u8; 16],
    pub operation_handle: Option<[u8; 16]>,
    pub input: Option<&'a [u8]>,
}

pub fn decode_foreground_request(bytes: &[u8]) -> Result<ForegroundRequest<'_>, ProtocolError> {
    crate::validate_deterministic_cbor(bytes)?;
    let mut reader = CborReader::new(bytes);
    decode_request_reader(&mut reader).and_then(|request| {
        if reader.is_complete() {
            Ok(request)
        } else {
            Err(ProtocolError::UnknownField)
        }
    })
}

pub fn decode_request_reader<'a>(
    reader: &mut CborReader<'a>,
) -> Result<ForegroundRequest<'a>, ProtocolError> {
    let count = reader.map()?;
    if !(7..=9).contains(&count) {
        return Err(ProtocolError::MissingField);
    }
    expect_unsigned(reader, 0, 1)?;
    expect_unsigned(reader, 1, 3)?;
    expect_unsigned(reader, 2, 1)?;
    expect_unsigned(reader, 3, 2)?;
    expect_unsigned(reader, 4, 4)?;
    expect_key(reader, 5)?;
    let attestation_challenge = reader.bytes()?;
    if !(MIN_ATTESTATION_CHALLENGE_BYTES..=MAX_ATTESTATION_CHALLENGE_BYTES)
        .contains(&attestation_challenge.len())
    {
        return Err(ProtocolError::LengthOutOfRange);
    }
    expect_key(reader, 6)?;
    let alias_handle = fixed(reader.bytes()?)?;
    let operation_handle = if count >= 8 {
        expect_key(reader, 7)?;
        Some(fixed(reader.bytes()?)?)
    } else {
        None
    };
    let input = if count == 9 {
        expect_key(reader, 8)?;
        let value = reader.bytes()?;
        if value.len() > MAX_OPERATION_INPUT_BYTES {
            return Err(ProtocolError::LengthOutOfRange);
        }
        Some(value)
    } else {
        None
    };
    Ok(ForegroundRequest {
        attestation_challenge,
        alias_handle,
        operation_handle,
        input,
    })
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
