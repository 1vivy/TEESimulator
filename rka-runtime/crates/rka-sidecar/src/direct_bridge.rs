use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};
use rka_state::RkpLeaseBatch;

use crate::{
    bridge::{
        BridgeError, BridgeMessage, BrokerOperation, CandidateBridgeOperation, PublicBytes,
        RoleExecutor, SidecarRole,
    },
    provisioning_io::{FileStateStore, load_lease_chain},
};

const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_UPDATE_BYTES: usize = 65_536;
const MAX_CHAIN_BYTES: usize = 524_288;
const MAX_CERTIFICATE_BYTES: usize = 65_536;

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling direct-session runtime owns this private bridge adapter"
)]
pub(crate) struct DirectBridgeAdapter {
    state_root: PathBuf,
    candidate_identity: Option<[u8; 32]>,
    executor: RoleExecutor,
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling direct-session runtime owns this private prepared request"
)]
pub(crate) struct PreparedBridgeRequest {
    request: BridgeMessage,
    plan: ResponsePlan,
}

impl PreparedBridgeRequest {
    pub(super) const fn request(&self) -> &BridgeMessage {
        &self.request
    }
}

#[derive(Clone, Copy)]
enum ResponsePlan {
    Generate { epoch: u64 },
    KeyLookup,
    List,
    Unit,
    Update { input_bytes: usize },
    Begin,
    Finish,
}

impl DirectBridgeAdapter {
    pub(super) fn new(state_root: &Path) -> Self {
        Self {
            state_root: state_root.to_path_buf(),
            candidate_identity: None,
            executor: RoleExecutor::new(SidecarRole::Donor),
        }
    }

    pub(super) fn prepare(&mut self, request: BridgeMessage) -> Result<PreparedBridgeRequest, ()> {
        let BridgeMessage::CandidateCommand(request_id, operation, payload) = request else {
            return Err(());
        };
        let (translated, plan) = match operation {
            CandidateBridgeOperation::Generate => self.generate(payload.as_slice())?,
            CandidateBridgeOperation::List => {
                let identity = exact::<32>(payload.as_slice())?;
                self.admit_identity(identity)?;
                (Vec::new(), ResponsePlan::List)
            }
            CandidateBridgeOperation::Get => {
                exact::<16>(payload.as_slice())?;
                (payload.as_slice().to_vec(), ResponsePlan::KeyLookup)
            }
            CandidateBridgeOperation::Delete | CandidateBridgeOperation::Abort => {
                if operation == CandidateBridgeOperation::Delete {
                    exact::<16>(payload.as_slice())?;
                } else {
                    operation_input(payload.as_slice(), 0)?;
                }
                (payload.as_slice().to_vec(), ResponsePlan::Unit)
            }
            CandidateBridgeOperation::Begin => {
                exact::<16>(payload.as_slice())?;
                (payload.as_slice().to_vec(), ResponsePlan::Begin)
            }
            CandidateBridgeOperation::UpdateAad | CandidateBridgeOperation::Update => {
                let input_bytes = operation_input(payload.as_slice(), MAX_UPDATE_BYTES)?;
                (
                    payload.as_slice().to_vec(),
                    ResponsePlan::Update { input_bytes },
                )
            }
            CandidateBridgeOperation::Finish => {
                operation_input(payload.as_slice(), MAX_UPDATE_BYTES)?;
                (payload.as_slice().to_vec(), ResponsePlan::Finish)
            }
        };
        Ok(PreparedBridgeRequest {
            request: BridgeMessage::CandidateCommand(
                request_id,
                operation,
                PublicBytes::bounded(&translated, 0, MAX_FRAME_BYTES).map_err(|_| ())?,
            ),
            plan,
        })
    }

    pub(super) fn dispatch(
        &self,
        prepared: &PreparedBridgeRequest,
    ) -> Result<BridgeMessage, BridgeError> {
        self.executor.dispatch(BrokerOperation::Donor {
            socket_path: &self.state_root.join("run/sockets/broker.sock"),
            request: prepared.request(),
        })
    }

    pub(super) fn finish(
        prepared: &PreparedBridgeRequest,
        response: BridgeMessage,
    ) -> Result<BridgeMessage, ()> {
        if let BridgeMessage::Error(..) = response {
            return Ok(response);
        }
        let BridgeMessage::CandidateReply(request_id, operation, payload) = response else {
            return Err(());
        };
        let BridgeMessage::CandidateCommand(expected_id, expected_operation, _) = &prepared.request
        else {
            return Err(());
        };
        if request_id != *expected_id || operation != *expected_operation {
            return Err(());
        }
        let translated = translate_response(prepared.plan, payload.as_slice())?;
        Ok(BridgeMessage::CandidateReply(
            request_id,
            operation,
            PublicBytes::bounded(&translated, 0, MAX_FRAME_BYTES).map_err(|_| ())?,
        ))
    }

    fn generate(&mut self, payload: &[u8]) -> Result<(Vec<u8>, ResponsePlan), ()> {
        let mut cursor = Cursor::new(payload);
        let alias = cursor.array::<16>()?;
        let identity = cursor.array::<32>()?;
        let challenge = cursor.bounded(16, 64)?;
        let aaid = cursor.bounded(1, 131_072)?;
        cursor.finish()?;
        self.admit_identity(identity)?;
        let batch =
            RkpLeaseBatch::load_active(&FileStateStore::new(&self.state_root)).map_err(|_| ())?;
        let lease = batch.leases().first().ok_or(())?.metadata();
        if batch.leases().len() != 1 {
            return Err(());
        }
        let chain =
            load_lease_chain(&self.state_root, lease.remote_handle.as_bytes()).map_err(|_| ())?;
        if chain.len() != usize::from(lease.chain.certificate_count)
            || !(2..=20).contains(&chain.len())
            || chain.iter().map(Vec::len).sum::<usize>() > MAX_CHAIN_BYTES
        {
            return Err(());
        }
        let transcript = transcript((&alias, &identity, challenge, aaid), lease.profile_epoch);
        let mut translated = Vec::new();
        translated.extend_from_slice(&alias);
        translated.extend_from_slice(lease.remote_handle.as_bytes());
        put_bytes(&mut translated, challenge)?;
        put_bytes(&mut translated, aaid)?;
        put_bytes(&mut translated, &transcript)?;
        translated.push(u8::try_from(chain.len()).map_err(|_| ())?);
        for certificate in chain {
            if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
                return Err(());
            }
            put_bytes(&mut translated, &certificate)?;
        }
        Ok((
            translated,
            ResponsePlan::Generate {
                epoch: lease.profile_epoch,
            },
        ))
    }

    fn admit_identity(&mut self, identity: [u8; 32]) -> Result<(), ()> {
        match self.candidate_identity {
            Some(expected) if expected != identity => Err(()),
            Some(_) => Ok(()),
            None => {
                self.candidate_identity = Some(identity);
                Ok(())
            }
        }
    }
}

fn translate_response(plan: ResponsePlan, payload: &[u8]) -> Result<Vec<u8>, ()> {
    match plan {
        ResponsePlan::Generate { epoch } => translate_generated(payload, epoch),
        ResponsePlan::KeyLookup => {
            parse_key_reply(payload)?;
            Ok(Vec::new())
        }
        ResponsePlan::List => {
            let mut cursor = Cursor::new(payload);
            let count = usize::from(cursor.byte()?);
            if count > 20 {
                return Err(());
            }
            for _ in 0..count {
                cursor.array::<16>()?;
            }
            cursor.finish()?;
            Ok(payload.to_vec())
        }
        ResponsePlan::Unit => {
            if payload.is_empty() {
                Ok(Vec::new())
            } else {
                Err(())
            }
        }
        ResponsePlan::Update { input_bytes } => {
            let mut cursor = Cursor::new(payload);
            let consumed = usize::try_from(cursor.u32()?).map_err(|_| ())?;
            let output = cursor.bounded(0, MAX_FRAME_BYTES)?;
            cursor.finish()?;
            if consumed == input_bytes && output.is_empty() {
                Ok(Vec::new())
            } else {
                Err(())
            }
        }
        ResponsePlan::Begin => {
            exact::<16>(payload)?;
            Ok(payload.to_vec())
        }
        ResponsePlan::Finish => {
            let mut cursor = Cursor::new(payload);
            cursor.bounded(0, MAX_FRAME_BYTES.saturating_sub(4))?;
            cursor.finish()?;
            Ok(payload.to_vec())
        }
    }
}

fn translate_generated(payload: &[u8], epoch: u64) -> Result<Vec<u8>, ()> {
    let parsed = parse_key_reply(payload)?;
    let epoch = i64::try_from(epoch).map_err(|_| ())?;
    let mut translated = Vec::new();
    translated.extend_from_slice(&parsed.handle);
    translated.extend_from_slice(&epoch.to_be_bytes());
    translated.extend_from_slice(&epoch.to_be_bytes());
    translated.extend_from_slice(&[0, 0, 0, 0, 0]);
    translated.push(u8::try_from(parsed.chain.len()).map_err(|_| ())?);
    for certificate in parsed.chain {
        put_bytes(&mut translated, certificate)?;
    }
    Ok(translated)
}

struct KeyReply<'a> {
    handle: [u8; 16],
    chain: Vec<&'a [u8]>,
}

fn parse_key_reply(payload: &[u8]) -> Result<KeyReply<'_>, ()> {
    let mut cursor = Cursor::new(payload);
    let handle = cursor.array::<16>()?;
    cursor.bounded(1, MAX_CERTIFICATE_BYTES)?;
    let count = usize::from(cursor.byte()?);
    if !(2..=20).contains(&count) {
        return Err(());
    }
    let mut chain = Vec::with_capacity(count);
    let mut chain_bytes = 0_usize;
    for _ in 0..count {
        let certificate = cursor.bounded(1, MAX_CERTIFICATE_BYTES)?;
        chain_bytes = chain_bytes.checked_add(certificate.len()).ok_or(())?;
        chain.push(certificate);
    }
    if chain_bytes > MAX_CHAIN_BYTES {
        return Err(());
    }
    cursor.bounded(0, MAX_FRAME_BYTES)?;
    cursor.finish()?;
    Ok(KeyReply { handle, chain })
}

fn operation_input(payload: &[u8], maximum: usize) -> Result<usize, ()> {
    let mut cursor = Cursor::new(payload);
    cursor.array::<16>()?;
    let input = cursor.bounded(0, maximum)?;
    cursor.finish()?;
    Ok(input.len())
}

fn exact<const N: usize>(payload: &[u8]) -> Result<[u8; N], ()> {
    payload.try_into().map_err(|_| ())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ()> {
    output.extend_from_slice(&u32::try_from(value.len()).map_err(|_| ())?.to_be_bytes());
    output.extend_from_slice(value);
    if output.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    Ok(())
}

fn transcript(request: (&[u8; 16], &[u8; 32], &[u8], &[u8]), epoch: u64) -> [u8; 32] {
    let (alias, identity, challenge, aaid) = request;
    let mut context = Context::new(&SHA256);
    context.update(b"TEESimulator-RS candidate request v1\0");
    for value in [alias.as_slice(), identity.as_slice(), challenge, aaid] {
        context.update(&value.len().to_be_bytes());
        context.update(value);
    }
    context.update(&epoch.to_be_bytes());
    let mut value = [0_u8; 32];
    value.copy_from_slice(context.finish().as_ref());
    value
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ()> {
        let end = self.offset.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.offset..end).ok_or(())?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        self.take(N)?.try_into().map_err(|_| ())
    }

    fn byte(&mut self) -> Result<u8, ()> {
        self.take(1)?.first().copied().ok_or(())
    }

    fn u32(&mut self) -> Result<u32, ()> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn bounded(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8], ()> {
        let length = usize::try_from(self.u32()?).map_err(|_| ())?;
        if length < minimum || length > maximum {
            return Err(());
        }
        self.take(length)
    }

    const fn finish(&self) -> Result<(), ()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}
