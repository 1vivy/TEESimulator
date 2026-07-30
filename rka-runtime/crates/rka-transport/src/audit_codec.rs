use rka_protocol::{CborWriter, HashDomain, hash_cbor};

use crate::{
    AuditEntry,
    audit::{AuditError, ReceiptContext},
};

#[doc(hidden)]
pub fn entry_cbor(entry: AuditEntry) -> Vec<u8> {
    let mut detail = CborWriter::with_capacity(8);
    detail.map(2);
    detail.unsigned(0);
    detail.unsigned(entry.stage.into());
    detail.unsigned(1);
    detail.unsigned(entry.request_kind.into());
    let mut prefix = CborWriter::with_capacity(24);
    prefix.map(2);
    prefix.unsigned(0);
    prefix.unsigned(entry.error.into());
    prefix.unsigned(1);
    let mut preimage = prefix.finish();
    preimage.extend_from_slice(&detail.finish());
    let detail_hash = hash_cbor(HashDomain::Audit, &preimage);
    let mut writer = CborWriter::with_capacity(80);
    writer.map(4);
    writer.unsigned(0);
    writer.unsigned(entry.stage.into());
    writer.unsigned(1);
    writer.unsigned(entry.request_kind.into());
    writer.unsigned(2);
    writer.bytes(&detail_hash);
    writer.unsigned(3);
    writer.bytes(&entry.correlation_hash);
    writer.finish()
}

#[doc(hidden)]
pub fn receipt_body(context: ReceiptContext, state: ([u8; 32], u64)) -> Vec<u8> {
    let (epoch, transport, correlation) = context.parts();
    let mut writer = CborWriter::with_capacity(96);
    writer.map(5);
    writer.unsigned(0);
    writer.unsigned(epoch);
    writer.unsigned(1);
    writer.unsigned(transport.tag());
    writer.unsigned(2);
    writer.bytes(&correlation);
    writer.unsigned(3);
    writer.bytes(&state.0);
    writer.unsigned(4);
    writer.unsigned(state.1);
    writer.finish()
}

#[doc(hidden)]
pub fn encode_state(sequence: u64, head: [u8; 32]) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(48);
    writer.array(2);
    writer.unsigned(sequence);
    writer.bytes(&head);
    writer.finish()
}

#[doc(hidden)]
pub fn decode_state(bytes: &[u8]) -> Result<(u64, [u8; 32]), AuditError> {
    if bytes.first() != Some(&0x82) {
        return Err(AuditError::Corrupt);
    }
    let (sequence, offset) = decode_unsigned(bytes, 1)?;
    let marker = *bytes.get(offset).ok_or(AuditError::Corrupt)?;
    let head = bytes
        .get(offset.saturating_add(2)..)
        .and_then(|value| <[u8; 32]>::try_from(value).ok())
        .ok_or(AuditError::Corrupt)?;
    if marker != 0x58 || bytes.get(offset.saturating_add(1)) != Some(&32) {
        return Err(AuditError::Corrupt);
    }
    Ok((sequence, head))
}

fn decode_unsigned(bytes: &[u8], offset: usize) -> Result<(u64, usize), AuditError> {
    let initial = *bytes.get(offset).ok_or(AuditError::Corrupt)?;
    match initial {
        value @ 0..=23 => Ok((u64::from(value), offset.saturating_add(1))),
        0x18 => Ok((
            u64::from(
                *bytes
                    .get(offset.saturating_add(1))
                    .ok_or(AuditError::Corrupt)?,
            ),
            offset.saturating_add(2),
        )),
        0x19 => {
            let value = bytes
                .get(offset.saturating_add(1)..offset.saturating_add(3))
                .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
                .ok_or(AuditError::Corrupt)?;
            Ok((
                u64::from(u16::from_be_bytes(value)),
                offset.saturating_add(3),
            ))
        }
        _ => Err(AuditError::Corrupt),
    }
}
