//! Recursive deterministic-CBOR structural validation.

use crate::{MAX_CBOR_DEPTH, MAX_FRAME_BYTES, ProtocolError, cbor::CborReader};

pub fn validate_deterministic_cbor(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyPayload);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::PayloadTooLarge {
            actual: bytes.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut reader = CborReader::new(bytes);
    validate_item(&mut reader, 1)?;
    if !reader.is_complete() {
        return Err(ProtocolError::NonCanonical);
    }
    Ok(())
}

pub fn validate_item(reader: &mut CborReader<'_>, depth: u8) -> Result<(), ProtocolError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(ProtocolError::DepthExceeded);
    }
    let initial = reader.peek()?;
    match initial >> 5 {
        0 => {
            reader.unsigned()?;
        }
        2 => {
            reader.bytes()?;
        }
        3 => {
            reader.text()?;
        }
        4 => {
            let count = reader.array()?;
            for _ in 0..count {
                validate_item(reader, depth.saturating_add(1))?;
            }
        }
        5 => validate_map(reader, depth)?,
        7 if initial == 0xf4 || initial == 0xf5 => {
            reader.boolean()?;
        }
        _ => return Err(ProtocolError::WrongType),
    }
    Ok(())
}

fn validate_map(reader: &mut CborReader<'_>, depth: u8) -> Result<(), ProtocolError> {
    let count = reader.map()?;
    let mut previous = None;
    for _ in 0..count {
        let key = reader.unsigned().map_err(|error| match error {
            ProtocolError::WrongType => ProtocolError::NonIntegerKey,
            other => other,
        })?;
        if previous.is_some_and(|value| key <= value) {
            return Err(ProtocolError::DuplicateOrUnorderedKey);
        }
        previous = Some(key);
        validate_item(reader, depth.saturating_add(1))?;
    }
    Ok(())
}
