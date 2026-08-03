use super::BridgeError;
use std::io::ErrorKind;

use super::model::{
    BridgeMessage, BrokerBatchId, BrokerCertificationMetadata, BrokerKeyMetadata,
    CandidateBridgeOperation, Hash32, MAX_CERTIFICATE_BYTES, MAX_CHAIN_BYTES,
    MAX_CHAIN_CERTIFICATES, MAX_FRAME_BYTES, MAX_PUBLIC_KEYS, MAX_SYNTHETIC_LEASE_PKCS8_BYTES,
    MAX_TOTAL_INPUT_BYTES, MAX_UPDATE_BYTES, NetworkHandle, PublicBytes, RequestId, SecretBytes,
};

pub(super) fn decode_body(
    tag: u8,
    request_id: RequestId,
    body: &[u8],
) -> Result<BridgeMessage, BridgeError> {
    let mut cursor = Cursor::new(body);
    let message = match tag {
        1 => decode_public_key_request(request_id, &mut cursor)?,
        2 => decode_public_key_response(request_id, &mut cursor)?,
        3 => decode_update(request_id, &mut cursor)?,
        4 => decode_public_result(request_id, &mut cursor)?,
        5 => {
            let count = usize::from(cursor.take_u8()?);
            if count > MAX_PUBLIC_KEYS {
                return Err(BridgeError::NonCanonical);
            }
            let mut handles = Vec::with_capacity(count);
            for _ in 0..count {
                handles.push(Hash32::new(cursor.take_array()?));
            }
            let cleanup = match cursor.take_u8()? {
                0 => None,
                1 => {
                    let batch_id = BrokerBatchId::new(cursor.take_array()?);
                    let action_count = usize::from(cursor.take_u8()?);
                    if action_count
                        != count
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(1))
                            .ok_or(BridgeError::NonCanonical)?
                    {
                        return Err(BridgeError::NonCanonical);
                    }
                    let mut action_ids = Vec::with_capacity(action_count);
                    for _ in 0..action_count {
                        action_ids.push(Hash32::new(cursor.take_array()?));
                    }
                    Some((batch_id, action_ids))
                }
                _ => return Err(BridgeError::NonCanonical),
            };
            BridgeMessage::Cancel(request_id, handles, cleanup)
        }
        6 => {
            let code = cursor.take_u8()?;
            if !(1..=6).contains(&code) {
                return Err(BridgeError::NonCanonical);
            }
            BridgeMessage::Error(request_id, code, Hash32::new(cursor.take_array()?))
        }
        7 | 8 => {
            let operation = CandidateBridgeOperation::from_wire(cursor.take_u8()?)?;
            let payload = cursor.take_public(0, MAX_FRAME_BYTES.saturating_sub(5))?;
            if tag == 7 {
                BridgeMessage::CandidateCommand(request_id, operation, payload)
            } else {
                BridgeMessage::CandidateReply(request_id, operation, payload)
            }
        }
        9 => decode_certification_request(request_id, &mut cursor)?,
        10 => BridgeMessage::CertificationAck(
            request_id,
            BrokerBatchId::new(cursor.take_array()?),
            Hash32::new(cursor.take_array()?),
        ),
        11 => decode_synthetic_lease_probe_request(request_id, &mut cursor)?,
        12 => BridgeMessage::SyntheticLeaseProbeResponse {
            request_id,
            certificate_chain: decode_synthetic_chain(&mut cursor)?,
        },
        13 => decode_synthetic_lease_issue_request(request_id, &mut cursor)?,
        14 => BridgeMessage::SyntheticLeaseIssueResponse {
            request_id,
            lease_epoch: cursor.take_u64()?,
            certificate_chain: decode_synthetic_chain(&mut cursor)?,
        },
        _ => return Err(BridgeError::UnknownTag),
    };
    if cursor.remaining() != 0 {
        return Err(BridgeError::NonCanonical);
    }
    Ok(message)
}

fn decode_synthetic_lease_issue_request(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let candidate_nonce = Hash32::new(cursor.take_array()?);
    let profile_id_hash = Hash32::new(cursor.take_array()?);
    let requested_epoch = cursor.take_u64()?;
    let private_key_pkcs8 = cursor.take_secret(MAX_SYNTHETIC_LEASE_PKCS8_BYTES)?;
    let expected_spki = cursor.take_public(1, MAX_CERTIFICATE_BYTES)?;
    let challenge = cursor.take_public(16, 64)?;
    let aaid = cursor.take_public(1, 131_072)?;
    let certificate_not_before_millis = cursor.take_u64()?;
    let certificate_not_after_millis = cursor.take_u64()?;
    if certificate_not_after_millis <= certificate_not_before_millis {
        return Err(BridgeError::NonCanonical);
    }
    Ok(BridgeMessage::SyntheticLeaseIssueRequest {
        request_id,
        candidate_nonce,
        profile_id_hash,
        requested_epoch,
        private_key_pkcs8,
        expected_spki,
        challenge,
        aaid,
        certificate_not_before_millis,
        certificate_not_after_millis,
    })
}

fn decode_synthetic_lease_probe_request(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let rkp_handle = Hash32::new(cursor.take_array()?);
    let private_key_pkcs8 = cursor.take_secret(MAX_SYNTHETIC_LEASE_PKCS8_BYTES)?;
    let expected_spki = cursor.take_public(1, MAX_CERTIFICATE_BYTES)?;
    let challenge = cursor.take_public(16, 64)?;
    let aaid = cursor.take_public(1, 131_072)?;
    let certificate_not_before_millis = cursor.take_u64()?;
    let certificate_not_after_millis = cursor.take_u64()?;
    if certificate_not_after_millis <= certificate_not_before_millis {
        return Err(BridgeError::NonCanonical);
    }
    Ok(BridgeMessage::SyntheticLeaseProbeRequest {
        request_id,
        rkp_handle,
        private_key_pkcs8,
        expected_spki,
        challenge,
        aaid,
        certificate_not_before_millis,
        certificate_not_after_millis,
        certificate_chain: decode_synthetic_chain(cursor)?,
    })
}

fn decode_synthetic_chain(cursor: &mut Cursor<'_>) -> Result<Vec<PublicBytes>, BridgeError> {
    let count = usize::from(cursor.take_u8()?);
    if !(2..=MAX_CHAIN_CERTIFICATES).contains(&count) {
        return Err(BridgeError::NonCanonical);
    }
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(count)
        .map_err(|_| BridgeError::Allocation)?;
    let mut total = 0_usize;
    for _ in 0..count {
        let certificate = cursor.take_public(1, MAX_CERTIFICATE_BYTES)?;
        total = total
            .checked_add(certificate.as_slice().len())
            .ok_or(BridgeError::ValueTooLarge)?;
        if total > MAX_CHAIN_BYTES {
            return Err(BridgeError::ValueTooLarge);
        }
        chain.push(certificate);
    }
    Ok(chain)
}

fn decode_public_key_request(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let key_count = cursor.take_u8()?;
    if !(1..=20).contains(&key_count) {
        return Err(BridgeError::NonCanonical);
    }
    let challenge = cursor.take_public(16, 64)?;
    Ok(BridgeMessage::PublicKeyRequest(
        request_id, challenge, key_count,
    ))
}

fn decode_public_key_response(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let public_csr = cursor.take_public(1, MAX_FRAME_BYTES)?;
    let batch_id = BrokerBatchId::new(cursor.take_array()?);
    let irpc_identity_hash = Hash32::new(cursor.take_array()?);
    let count = usize::from(cursor.take_u8()?);
    if !(1..=MAX_PUBLIC_KEYS).contains(&count) {
        return Err(BridgeError::NonCanonical);
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| BridgeError::Allocation)?;
    for expected_order in 0..count {
        let order = cursor.take_u8()?;
        if usize::from(order) != expected_order {
            return Err(BridgeError::NonCanonical);
        }
        keys.push(BrokerKeyMetadata::new(
            order,
            cursor.take_array()?,
            cursor.take_array()?,
            cursor.take_array()?,
        )?);
    }
    Ok(BridgeMessage::PublicKeyResponse(
        request_id,
        public_csr,
        batch_id,
        irpc_identity_hash,
        keys,
    ))
}

fn decode_certification_request(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let batch_id = BrokerBatchId::new(cursor.take_array()?);
    let count = usize::from(cursor.take_u8()?);
    if !(1..=MAX_PUBLIC_KEYS).contains(&count) {
        return Err(BridgeError::NonCanonical);
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| BridgeError::Allocation)?;
    for expected_order in 0..count {
        let order = cursor.take_u8()?;
        if usize::from(order) != expected_order {
            return Err(BridgeError::NonCanonical);
        }
        keys.push(BrokerCertificationMetadata::new(
            order,
            cursor.take_array()?,
            cursor.take_array()?,
            cursor.take_array()?,
            cursor.take_array()?,
            cursor.take_u8()?,
        )?);
    }
    Ok(BridgeMessage::CertificationRequest(
        request_id,
        batch_id,
        keys,
        cursor.take_u64()?,
        Hash32::new(cursor.take_array()?),
    ))
}

fn decode_update(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let operation_handle = NetworkHandle::new(cursor.take_array()?);
    let total_input_bytes = cursor.take_u32()?;
    let chunk = cursor.take_public(0, MAX_UPDATE_BYTES)?;
    let chunk_length =
        u32::try_from(chunk.as_slice().len()).map_err(|_| BridgeError::ValueTooLarge)?;
    if total_input_bytes < chunk_length
        || usize::try_from(total_input_bytes).map_err(|_| BridgeError::ValueTooLarge)?
            > MAX_TOTAL_INPUT_BYTES
    {
        return Err(BridgeError::NonCanonical);
    }
    Ok(BridgeMessage::UpdateRequest(
        request_id,
        operation_handle,
        chunk,
        total_input_bytes,
    ))
}

fn decode_public_result(
    request_id: RequestId,
    cursor: &mut Cursor<'_>,
) -> Result<BridgeMessage, BridgeError> {
    let network_handle = NetworkHandle::new(cursor.take_array()?);
    let public_spki = cursor.take_public(1, MAX_CERTIFICATE_BYTES)?;
    let count = usize::from(cursor.take_u8()?);
    if !(1..=MAX_CHAIN_CERTIFICATES).contains(&count) {
        return Err(BridgeError::NonCanonical);
    }
    let mut certificate_chain = Vec::new();
    certificate_chain
        .try_reserve_exact(count)
        .map_err(|_| BridgeError::Allocation)?;
    let mut total = 0_usize;
    for _ in 0..count {
        let certificate = cursor.take_public(1, MAX_CERTIFICATE_BYTES)?;
        total = total
            .checked_add(certificate.as_slice().len())
            .ok_or(BridgeError::ValueTooLarge)?;
        if total > MAX_CHAIN_BYTES {
            return Err(BridgeError::ValueTooLarge);
        }
        certificate_chain.push(certificate);
    }
    Ok(BridgeMessage::PublicResult(
        request_id,
        network_handle,
        public_spki,
        certificate_chain,
    ))
}

pub(super) fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), BridgeError> {
    let length = u32::try_from(bytes.len()).map_err(|_| BridgeError::ValueTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn byte(bytes: &[u8], index: usize) -> Result<u8, BridgeError> {
    bytes.get(index).copied().ok_or(BridgeError::Truncated)
}

pub(super) fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], BridgeError> {
    let end = start.checked_add(N).ok_or(BridgeError::Truncated)?;
    bytes
        .get(start..end)
        .ok_or(BridgeError::Truncated)?
        .try_into()
        .map_err(|_| BridgeError::Truncated)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BridgeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BridgeError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BridgeError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, BridgeError> {
        let value = self.take(1)?;
        value.first().copied().ok_or(BridgeError::Truncated)
    }

    fn take_u32(&mut self) -> Result<u32, BridgeError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, BridgeError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], BridgeError> {
        self.take(N)?.try_into().map_err(|_| BridgeError::Truncated)
    }

    fn take_public(&mut self, minimum: usize, maximum: usize) -> Result<PublicBytes, BridgeError> {
        let length = usize::try_from(self.take_u32()?).map_err(|_| BridgeError::ValueTooLarge)?;
        if length < minimum || length > maximum {
            return Err(BridgeError::ValueTooLarge);
        }
        PublicBytes::bounded(self.take(length)?, minimum, maximum)
    }

    fn take_secret(&mut self, maximum: usize) -> Result<SecretBytes, BridgeError> {
        let length = usize::try_from(self.take_u32()?).map_err(|_| BridgeError::ValueTooLarge)?;
        SecretBytes::bounded(self.take(length)?, maximum)
    }
}

pub(super) fn map_read_error(error: &std::io::Error) -> BridgeError {
    let mapped = map_io_error(error);
    if mapped == BridgeError::Io {
        BridgeError::Truncated
    } else {
        mapped
    }
}

pub(super) fn map_io_error(error: &std::io::Error) -> BridgeError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => BridgeError::Deadline,
        ErrorKind::BrokenPipe
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::NotConnected
        | ErrorKind::UnexpectedEof => BridgeError::PeerDied,
        _ => BridgeError::Io,
    }
}
