use std::path::{Path, PathBuf};

use rka_protocol::{CborWriter, HashDomain, hash_bytes, hash_cbor};

use crate::bridge::{
    BridgeMessage, BrokerOperation, CandidateBridgeOperation, PublicBytes, RequestId, RoleExecutor,
    SidecarRole,
};

use super::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
    RemoteKeyHandle, RemoteOperationHandle,
};

/// Android broker client backed by the authenticated donor Unix bridge.
#[derive(Debug)]
pub struct BridgeDonorBroker {
    socket: PathBuf,
    executor: RoleExecutor,
    next_request: u64,
}

impl BridgeDonorBroker {
    /// Creates one donor-only bridge client.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
            executor: RoleExecutor::new(SidecarRole::Donor),
            next_request: 1,
        }
    }

    fn exchange(
        &mut self,
        operation: CandidateBridgeOperation,
        payload: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let request_id = RequestId::new(self.next_request);
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(BrokerFailure::Unavailable)?;
        let request = BridgeMessage::CandidateCommand(
            request_id,
            operation,
            PublicBytes::bounded(payload, 0, 1_048_571).map_err(|_| BrokerFailure::Rejected)?,
        );
        let response = self
            .executor
            .dispatch(BrokerOperation::Donor {
                socket_path: &self.socket,
                request: &request,
            })
            .map_err(|_| BrokerFailure::Unavailable)?;
        match response {
            BridgeMessage::CandidateReply(id, returned, bytes)
                if id == request_id && returned == operation =>
            {
                Ok(bytes.as_slice().to_vec())
            }
            BridgeMessage::Error(..) => Err(BrokerFailure::Rejected),
            _ => Err(BrokerFailure::Unavailable),
        }
    }
}

impl DonorBroker for BridgeDonorBroker {
    fn generate(&mut self, request: BrokerGenerate<'_>) -> Result<GeneratedKey, BrokerFailure> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&request.alias);
        payload.extend_from_slice(&request.rkp_handle.as_array());
        put_bytes(&mut payload, request.challenge)?;
        put_bytes(&mut payload, request.candidate_aaid)?;
        put_bytes(&mut payload, &request.prior_transcript_hash)?;
        payload.push(u8::try_from(request.rkp_chain.len()).map_err(|_| BrokerFailure::Rejected)?);
        for certificate in request.rkp_chain {
            put_bytes(&mut payload, certificate)?;
        }
        let response = self.exchange(CandidateBridgeOperation::Generate, &payload)?;
        decode_public_key(&response)
    }

    fn begin(&mut self, request: BrokerBegin) -> Result<RemoteOperationHandle, BrokerFailure> {
        let response = self.exchange(
            CandidateBridgeOperation::Begin,
            &request.key_handle.as_array(),
        )?;
        Ok(RemoteOperationHandle::new(
            response.try_into().map_err(|_| BrokerFailure::Rejected)?,
        ))
    }

    fn update_aad(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<usize, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::UpdateAad, operation, input)?;
        decode_update(&response).map(|(consumed, _)| consumed)
    }

    fn update(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Update, operation, input)?;
        decode_update(&response).map(|(_, output)| output)
    }

    fn finish(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Finish, operation, input)?;
        let mut cursor = Cursor::new(&response);
        let signature = cursor.bytes(1, 65_536)?;
        cursor.finish()?;
        Ok(signature)
    }

    fn abort(&mut self, operation: RemoteOperationHandle) -> Result<(), BrokerFailure> {
        let response = self.operation(CandidateBridgeOperation::Abort, operation, &[])?;
        if response.is_empty() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }

    fn delete(&mut self, key: RemoteKeyHandle) -> Result<(), BrokerFailure> {
        let response = self.exchange(CandidateBridgeOperation::Delete, &key.as_array())?;
        if response.is_empty() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }

    fn get(&mut self, key: RemoteKeyHandle) -> Result<PublicKeyResult, BrokerFailure> {
        let response = self.exchange(CandidateBridgeOperation::Get, &key.as_array())?;
        decode_public_key(&response)
    }
}

impl BridgeDonorBroker {
    fn operation(
        &mut self,
        kind: CandidateBridgeOperation,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        let mut payload = Vec::with_capacity(20_usize.saturating_add(input.len()));
        payload.extend_from_slice(&operation.as_array());
        put_bytes(&mut payload, input)?;
        self.exchange(kind, &payload)
    }
}

fn decode_public_key(response: &[u8]) -> Result<GeneratedKey, BrokerFailure> {
    let mut cursor = Cursor::new(response);
    let handle = RemoteKeyHandle::new(cursor.array()?);
    let spki = cursor.bytes(1, 65_536)?;
    let count = usize::from(cursor.u8()?);
    if !(2..=20).contains(&count) {
        return Err(BrokerFailure::Rejected);
    }
    let mut chain = Vec::with_capacity(count);
    for _ in 0..count {
        chain.push(cursor.bytes(1, 65_536)?);
    }
    let _transcript_signature = cursor.bytes(1, 65_536)?;
    cursor.finish()?;
    Ok(GeneratedKey::new(
        handle,
        chain,
        hash_bytes(HashDomain::RkpPublic, &spki),
        exact_characteristics_hash(),
    ))
}

fn decode_update(response: &[u8]) -> Result<(usize, Vec<u8>), BrokerFailure> {
    let mut cursor = Cursor::new(response);
    let consumed = usize::try_from(cursor.u32()?).map_err(|_| BrokerFailure::Rejected)?;
    let output = cursor.bytes(0, 65_536)?;
    cursor.finish()?;
    Ok((consumed, output))
}

fn exact_characteristics_hash() -> [u8; 32] {
    let mut writer = CborWriter::with_capacity(32);
    writer.map(8);
    for (key, value) in [(0, 1), (1, 3), (2, 1)] {
        writer.unsigned(key);
        writer.unsigned(value);
    }
    writer.unsigned(3);
    writer.array(1);
    writer.unsigned(2);
    writer.unsigned(4);
    writer.array(1);
    writer.unsigned(4);
    writer.unsigned(5);
    writer.unsigned(0);
    writer.unsigned(6);
    writer.boolean(true);
    writer.unsigned(7);
    writer.boolean(false);
    hash_cbor(HashDomain::Profile, &writer.finish())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BrokerFailure> {
    let length = u32::try_from(value.len()).map_err(|_| BrokerFailure::Rejected)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BrokerFailure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BrokerFailure::Rejected)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BrokerFailure::Rejected)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BrokerFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| BrokerFailure::Rejected)
    }

    fn u8(&mut self) -> Result<u8, BrokerFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(BrokerFailure::Rejected)
    }

    fn u32(&mut self) -> Result<u32, BrokerFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn bytes(&mut self, minimum: usize, maximum: usize) -> Result<Vec<u8>, BrokerFailure> {
        let length = usize::try_from(self.u32()?).map_err(|_| BrokerFailure::Rejected)?;
        if length < minimum || length > maximum {
            return Err(BrokerFailure::Rejected);
        }
        Ok(self.take(length)?.to_vec())
    }

    const fn finish(self) -> Result<(), BrokerFailure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BrokerFailure::Rejected)
        }
    }
}
