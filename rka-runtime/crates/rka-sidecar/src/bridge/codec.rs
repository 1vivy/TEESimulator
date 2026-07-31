use std::io::Read;

use super::model::{
    BridgeMessage, ExchangeRole, HEADER_BYTES, MAGIC, MAX_FRAME_BYTES, RequestId, VERSION,
};
use super::{
    BridgeError,
    decode_body::{array, byte, decode_body, map_read_error, put_bytes},
};

/// Encoded bytes wiped on release.
#[derive(Debug, Eq, PartialEq)]
pub struct EncodedFrame(Vec<u8>);

impl EncodedFrame {
    /// Borrows encoded bytes until deterministic wipe.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for EncodedFrame {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Encodes one deterministic Task 7 RKB1 frame.
pub fn encode_frame(
    message: &BridgeMessage,
    role: ExchangeRole,
) -> Result<EncodedFrame, BridgeError> {
    if !role.accepts(message.tag()) {
        return Err(BridgeError::UnexpectedTag);
    }
    let body_length = body_length(message)?;
    if body_length == 0 || body_length > MAX_FRAME_BYTES {
        return Err(BridgeError::FrameTooLarge);
    }
    let total = HEADER_BYTES
        .checked_add(body_length)
        .ok_or(BridgeError::FrameTooLarge)?;
    let length = u32::try_from(body_length).map_err(|_| BridgeError::FrameTooLarge)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| BridgeError::Allocation)?;
    output.extend_from_slice(&MAGIC);
    output.extend_from_slice(&[VERSION, role.direction(), message.tag(), 0]);
    output.extend_from_slice(&message.request_id().value().to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&[0; 4]);
    encode_body(message, &mut output)?;
    Ok(EncodedFrame(output))
}

/// Decodes exactly one deterministic Task 7 RKB1 frame.
pub fn decode_frame(bytes: &[u8], role: ExchangeRole) -> Result<BridgeMessage, BridgeError> {
    let header = bytes.get(..HEADER_BYTES).ok_or(BridgeError::Truncated)?;
    let magic = header.get(..4).ok_or(BridgeError::Truncated)?;
    if magic != MAGIC {
        return Err(BridgeError::BadMagic);
    }
    let version = byte(header, 4)?;
    let direction = byte(header, 5)?;
    let tag = byte(header, 6)?;
    let flags = byte(header, 7)?;
    if version != VERSION {
        return Err(BridgeError::UnsupportedVersion);
    }
    if direction != role.direction() {
        return Err(BridgeError::WrongDirection);
    }
    if !(1..=10).contains(&tag) || matches!(tag, 7 | 8) {
        return Err(BridgeError::UnknownTag);
    }
    if !role.accepts(tag) {
        return Err(BridgeError::UnexpectedTag);
    }
    let request_id = RequestId::new(u64::from_be_bytes(array(header, 8)?));
    let body_length = usize::try_from(u32::from_be_bytes(array(header, 16)?))
        .map_err(|_| BridgeError::FrameTooLarge)?;
    if flags != 0 || u32::from_be_bytes(array(header, 20)?) != 0 {
        return Err(BridgeError::ReservedBits);
    }
    if body_length == 0 {
        return Err(BridgeError::EmptyFrame);
    }
    if body_length > MAX_FRAME_BYTES {
        return Err(BridgeError::FrameTooLarge);
    }
    let total = HEADER_BYTES
        .checked_add(body_length)
        .ok_or(BridgeError::FrameTooLarge)?;
    if bytes.len() < total {
        return Err(BridgeError::Truncated);
    }
    if bytes.len() != total {
        return Err(BridgeError::NonCanonical);
    }
    let body = bytes.get(HEADER_BYTES..).ok_or(BridgeError::Truncated)?;
    decode_body(tag, request_id, body)
}

/// Reads a header before allocating its bounded body.
pub fn read_frame(input: &mut impl Read, role: ExchangeRole) -> Result<BridgeMessage, BridgeError> {
    let mut header = [0_u8; HEADER_BYTES];
    input
        .read_exact(&mut header)
        .map_err(|error| map_read_error(&error))?;
    let body_length = usize::try_from(u32::from_be_bytes(array(&header, 16)?))
        .map_err(|_| BridgeError::FrameTooLarge)?;
    if body_length == 0 {
        return Err(BridgeError::EmptyFrame);
    }
    if body_length > MAX_FRAME_BYTES {
        return Err(BridgeError::FrameTooLarge);
    }
    let total = HEADER_BYTES
        .checked_add(body_length)
        .ok_or(BridgeError::FrameTooLarge)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| BridgeError::Allocation)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    let body = frame
        .get_mut(HEADER_BYTES..)
        .ok_or(BridgeError::Truncated)?;
    input
        .read_exact(body)
        .map_err(|error| map_read_error(&error))?;
    let result = decode_frame(&frame, role);
    frame.fill(0);
    result
}

fn body_length(message: &BridgeMessage) -> Result<usize, BridgeError> {
    let checked =
        |sum: usize, value: usize| sum.checked_add(value).ok_or(BridgeError::ValueTooLarge);
    match message {
        BridgeMessage::PublicKeyRequest(_, challenge, _) => checked(5, challenge.as_slice().len()),
        BridgeMessage::PublicKeyResponse(_, public_csr, _, keys) => {
            checked(21, public_csr.as_slice().len())?
                .checked_add(
                    keys.len()
                        .checked_mul(97)
                        .ok_or(BridgeError::ValueTooLarge)?,
                )
                .ok_or(BridgeError::ValueTooLarge)
        }
        BridgeMessage::UpdateRequest(_, _, chunk, _) => checked(24, chunk.as_slice().len()),
        BridgeMessage::PublicResult(_, _, public_spki, certificate_chain) => {
            certificate_chain.iter().try_fold(
                checked(21, public_spki.as_slice().len())?,
                |sum, certificate| checked(checked(sum, 4)?, certificate.as_slice().len()),
            )
        }
        BridgeMessage::Cancel(_, handles, cleanup) => {
            let base = handles
                .len()
                .checked_mul(32)
                .and_then(|length| length.checked_add(2))
                .ok_or(BridgeError::ValueTooLarge)?;
            cleanup.as_ref().map_or(Ok(base), |(_, action_ids)| {
                action_ids
                    .len()
                    .checked_mul(32)
                    .and_then(|length| length.checked_add(17))
                    .and_then(|length| length.checked_add(base))
                    .ok_or(BridgeError::ValueTooLarge)
            })
        }
        BridgeMessage::Error(..) => Ok(33),
        BridgeMessage::CertificationRequest(_, _, keys, _, _) => keys
            .len()
            .checked_mul(130)
            .and_then(|length| length.checked_add(57))
            .ok_or(BridgeError::ValueTooLarge),
        BridgeMessage::CertificationAck(..) => Ok(48),
    }
}

fn encode_body(message: &BridgeMessage, output: &mut Vec<u8>) -> Result<(), BridgeError> {
    match message {
        BridgeMessage::PublicKeyRequest(_, challenge, key_count) => {
            output.push(*key_count);
            put_bytes(output, challenge.as_slice())?;
        }
        BridgeMessage::PublicKeyResponse(_, public_csr, batch_id, keys) => {
            put_bytes(output, public_csr.as_slice())?;
            output.extend_from_slice(batch_id.as_array());
            output.push(u8::try_from(keys.len()).map_err(|_| BridgeError::ValueTooLarge)?);
            for (order, key) in keys.iter().enumerate() {
                if usize::from(key.order()) != order {
                    return Err(BridgeError::NonCanonical);
                }
                output.push(key.order());
                output.extend_from_slice(key.handle());
                output.extend_from_slice(key.public_key_hash());
                output.extend_from_slice(key.spki_hash());
            }
        }
        BridgeMessage::UpdateRequest(_, operation_handle, chunk, total_input_bytes) => {
            output.extend_from_slice(operation_handle.as_array());
            output.extend_from_slice(&total_input_bytes.to_be_bytes());
            put_bytes(output, chunk.as_slice())?;
        }
        BridgeMessage::PublicResult(_, network_handle, public_spki, certificate_chain) => {
            output.extend_from_slice(network_handle.as_array());
            put_bytes(output, public_spki.as_slice())?;
            output.push(
                u8::try_from(certificate_chain.len()).map_err(|_| BridgeError::ValueTooLarge)?,
            );
            for certificate in certificate_chain {
                put_bytes(output, certificate.as_slice())?;
            }
        }
        BridgeMessage::Cancel(_, handles, cleanup) => {
            output.push(u8::try_from(handles.len()).map_err(|_| BridgeError::ValueTooLarge)?);
            for handle in handles {
                output.extend_from_slice(handle.as_array());
            }
            match cleanup {
                None => output.push(0),
                Some((batch_id, action_ids)) => {
                    if action_ids.len()
                        != handles
                            .len()
                            .checked_mul(2)
                            .and_then(|count| count.checked_add(1))
                            .ok_or(BridgeError::ValueTooLarge)?
                    {
                        return Err(BridgeError::NonCanonical);
                    }
                    output.push(1);
                    output.extend_from_slice(batch_id.as_array());
                    output.push(
                        u8::try_from(action_ids.len()).map_err(|_| BridgeError::ValueTooLarge)?,
                    );
                    for action_id in action_ids {
                        output.extend_from_slice(action_id.as_array());
                    }
                }
            }
        }
        BridgeMessage::Error(_, code, detail_hash) => {
            output.push(*code);
            output.extend_from_slice(detail_hash.as_array());
        }
        BridgeMessage::CertificationRequest(_, batch_id, keys, epoch, activation_binding) => {
            output.extend_from_slice(batch_id.as_array());
            output.push(u8::try_from(keys.len()).map_err(|_| BridgeError::ValueTooLarge)?);
            for (order, key) in keys.iter().enumerate() {
                if usize::from(key.order()) != order {
                    return Err(BridgeError::NonCanonical);
                }
                output.push(key.order());
                output.extend_from_slice(key.handle());
                output.extend_from_slice(key.public_key_hash());
                output.extend_from_slice(key.spki_hash());
                output.extend_from_slice(key.chain_hash());
                output.push(key.certificate_count());
            }
            output.extend_from_slice(&epoch.to_be_bytes());
            output.extend_from_slice(activation_binding.as_array());
        }
        BridgeMessage::CertificationAck(_, batch_id, activation_binding) => {
            output.extend_from_slice(batch_id.as_array());
            output.extend_from_slice(activation_binding.as_array());
        }
    }
    Ok(())
}
