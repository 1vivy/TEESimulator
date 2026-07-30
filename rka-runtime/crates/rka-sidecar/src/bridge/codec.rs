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
    if !(1..=6).contains(&tag) {
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
        BridgeMessage::PublicKeyResponse(_, public_csr, hashes) => {
            checked(5, public_csr.as_slice().len())?
                .checked_add(
                    hashes
                        .len()
                        .checked_mul(32)
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
        BridgeMessage::Cancel(..) => Ok(1),
        BridgeMessage::Error(..) => Ok(33),
    }
}

fn encode_body(message: &BridgeMessage, output: &mut Vec<u8>) -> Result<(), BridgeError> {
    match message {
        BridgeMessage::PublicKeyRequest(_, challenge, key_count) => {
            output.push(*key_count);
            put_bytes(output, challenge.as_slice())?;
        }
        BridgeMessage::PublicKeyResponse(_, public_csr, hashes) => {
            put_bytes(output, public_csr.as_slice())?;
            output.push(u8::try_from(hashes.len()).map_err(|_| BridgeError::ValueTooLarge)?);
            for hash in hashes {
                output.extend_from_slice(hash.as_array());
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
        BridgeMessage::Cancel(..) => output.push(0),
        BridgeMessage::Error(_, code, detail_hash) => {
            output.push(*code);
            output.extend_from_slice(detail_hash.as_array());
        }
    }
    Ok(())
}
