//! Exact `HELLO_ACK`, `RESULT`, and `ERROR` response schemas.

use crate::{
    MAX_DER_CERTIFICATE_BYTES, MAX_REMOTE_KEYS, MAX_RETURNED_CHAIN_BYTES, MAX_UPDATE_BYTES,
    MessageKind, ProtocolError, cbor::CborReader, envelope::decode_envelope_reader,
};

pub fn validate_response_body(kind: MessageKind, bytes: &[u8]) -> Result<(), ProtocolError> {
    crate::validate_deterministic_cbor(bytes)?;
    let mut reader = CborReader::new(bytes);
    match kind {
        MessageKind::HelloAck => hello_ack(&mut reader)?,
        MessageKind::Result => result(&mut reader)?,
        MessageKind::Error => error(&mut reader)?,
        _ => return Err(ProtocolError::UnsupportedValue),
    }
    if !reader.is_complete() {
        return Err(ProtocolError::UnknownField);
    }
    Ok(())
}

pub fn validate_response_reader(
    reader: &mut CborReader<'_>,
    kind: MessageKind,
) -> Result<(), ProtocolError> {
    let start = reader.position();
    reader.skip_item()?;
    validate_response_body(kind, reader.slice_from(start)?)
}

fn hello_ack(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 4)?;
    expect_key(reader, 0)?;
    reader.boolean()?;
    expect_key(reader, 1)?;
    fixed::<32>(reader.bytes()?)?;
    expect_key(reader, 2)?;
    fixed::<32>(reader.bytes()?)?;
    expect_key(reader, 3)?;
    fixed::<32>(reader.bytes()?)?;
    Ok(())
}

fn error(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 5)?;
    expect_key(reader, 0)?;
    request_kind(reader.unsigned()?)?;
    expect_key(reader, 1)?;
    if !(1..=11).contains(&reader.unsigned()?) {
        return Err(ProtocolError::UnsupportedValue);
    }
    expect_key(reader, 2)?;
    if reader.boolean()? {
        return Err(ProtocolError::UnsupportedValue);
    }
    expect_key(reader, 3)?;
    reader.boolean()?;
    expect_key(reader, 4)?;
    fixed::<32>(reader.bytes()?)?;
    Ok(())
}

fn result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 2)?;
    expect_key(reader, 0)?;
    let triggering = request_kind(reader.unsigned()?)?;
    expect_key(reader, 1)?;
    match triggering {
        MessageKind::Generate | MessageKind::Get => generate_result(reader),
        MessageKind::List => list_result(reader),
        MessageKind::Delete | MessageKind::Abort => boolean_result(reader, 0),
        MessageKind::Begin => begin_result(reader),
        MessageKind::UpdateAad | MessageKind::Update => update_result(reader),
        MessageKind::Finish => finish_result(reader),
        _ => Err(ProtocolError::UnsupportedValue),
    }
}

fn generate_result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 5)?;
    expect_key(reader, 0)?;
    fixed::<16>(reader.bytes()?)?;
    expect_key(reader, 1)?;
    certificate_chain(reader)?;
    expect_key(reader, 2)?;
    fixed::<32>(reader.bytes()?)?;
    expect_key(reader, 3)?;
    decode_envelope_reader(reader)?;
    expect_key(reader, 4)?;
    leaf_proof(reader)
}

fn certificate_chain(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    let count = reader.array()?;
    if count < 2 {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let mut total = 0_usize;
    for _ in 0..count {
        let certificate = reader.bytes()?;
        if certificate.is_empty() || certificate.len() > MAX_DER_CERTIFICATE_BYTES {
            return Err(ProtocolError::LengthOutOfRange);
        }
        total = total
            .checked_add(certificate.len())
            .ok_or(ProtocolError::LengthOutOfRange)?;
    }
    if total > MAX_RETURNED_CHAIN_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    Ok(())
}

fn leaf_proof(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 6)?;
    for key in 0..5 {
        expect_key(reader, key)?;
        fixed::<32>(reader.bytes()?)?;
    }
    expect_key(reader, 5)?;
    if reader.bytes()?.is_empty() {
        return Err(ProtocolError::LengthOutOfRange);
    }
    Ok(())
}

fn list_result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 1)?;
    expect_key(reader, 0)?;
    let count = reader.array()?;
    if u64::try_from(count).map_or(true, |value| value > MAX_REMOTE_KEYS) {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let mut previous: Option<[u8; 16]> = None;
    for _ in 0..count {
        if reader.array()? != 3 {
            return Err(ProtocolError::MissingField);
        }
        let alias = fixed::<16>(reader.bytes()?)?;
        if previous.is_some_and(|value| value >= alias) {
            return Err(ProtocolError::InvalidOrdering);
        }
        previous = Some(alias);
        fixed::<32>(reader.bytes()?)?;
        if !(1..=4).contains(&reader.unsigned()?) {
            return Err(ProtocolError::UnsupportedValue);
        }
    }
    Ok(())
}

fn begin_result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 2)?;
    expect_key(reader, 0)?;
    fixed::<16>(reader.bytes()?)?;
    expect_key(reader, 1)?;
    if reader.unsigned()? != 65_536 {
        return Err(ProtocolError::UnsupportedValue);
    }
    Ok(())
}

fn update_result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 2)?;
    expect_key(reader, 0)?;
    u32::try_from(reader.unsigned()?).map_err(|_| ProtocolError::LengthOutOfRange)?;
    expect_key(reader, 1)?;
    if reader.bytes()?.len() > MAX_UPDATE_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    Ok(())
}

fn finish_result(reader: &mut CborReader<'_>) -> Result<(), ProtocolError> {
    expect_map(reader, 2)?;
    expect_key(reader, 0)?;
    if reader.bytes()?.is_empty() {
        return Err(ProtocolError::LengthOutOfRange);
    }
    expect_key(reader, 1)?;
    fixed::<32>(reader.bytes()?)?;
    Ok(())
}

fn boolean_result(reader: &mut CborReader<'_>, key: u64) -> Result<(), ProtocolError> {
    expect_map(reader, 1)?;
    expect_key(reader, key)?;
    reader.boolean()?;
    Ok(())
}

fn request_kind(value: u64) -> Result<MessageKind, ProtocolError> {
    let kind = MessageKind::try_from(value)?;
    match kind {
        MessageKind::Generate
        | MessageKind::Get
        | MessageKind::List
        | MessageKind::Delete
        | MessageKind::Begin
        | MessageKind::UpdateAad
        | MessageKind::Update
        | MessageKind::Finish
        | MessageKind::Abort => Ok(kind),
        MessageKind::Hello | MessageKind::HelloAck | MessageKind::Result | MessageKind::Error => {
            Err(ProtocolError::UnsupportedValue)
        }
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes
        .try_into()
        .map_err(|_| ProtocolError::LengthOutOfRange)
}

fn expect_map(reader: &mut CborReader<'_>, count: usize) -> Result<(), ProtocolError> {
    if reader.map()? == count {
        Ok(())
    } else {
        Err(ProtocolError::MissingField)
    }
}

fn expect_key(reader: &mut CborReader<'_>, key: u64) -> Result<(), ProtocolError> {
    if reader.unsigned()? == key {
        Ok(())
    } else {
        Err(ProtocolError::UnknownField)
    }
}
