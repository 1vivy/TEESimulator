#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_const_for_fn,
    clippy::too_many_arguments,
    clippy::unused_self,
    missing_docs,
    unreachable_pub,
    reason = "bounded test builders favor readable scenario assembly and observable call counts"
)]

use rka_protocol::{CborWriter, HashDomain, hash_bytes, hash_cbor};
use rka_sidecar::donor::{
    AccessContext, BeginRequest, BrokerBegin, BrokerFailure, BrokerGenerate, DeleteRequest,
    DonorBroker, FinishRequest, GenerateRequest, GeneratedKey, OperationRequest, PairedPolicy,
    PublicKeyResult, RemoteKeyHandle, RemoteOperationHandle,
};

const AAID: &[u8] = b"authoritative-aaid";
const LINEAGE_HASH: [u8; 32] = [0x22; 32];
const PROFILE_EPOCH: u64 = 9;
const CANDIDATE_NONCE: [u8; 32] = [0x33; 32];
const DONOR_NONCE: [u8; 32] = [0x44; 32];
const PEER: [u8; 32] = [0x55; 32];
const PROFILE: [u8; 32] = [0x66; 32];
const SESSION: [u8; 32] = [0x77; 32];
const IRPC: [u8; 32] = [0x88; 32];
const RKP_PUBLIC: [u8; 32] = [0x91; 32];
const CSR: [u8; 32] = [0x92; 32];
const SERVER_BODY: [u8; 32] = [0x93; 32];
const CHALLENGE: [u8; 32] = [0x94; 32];
const RESPONSE: [u8; 32] = [0x95; 32];
const CHAIN: [u8; 32] = [0x96; 32];
const ALIAS: [u8; 16] = [0xa1; 16];

#[derive(Debug)]
pub struct Fixture {
    identity: Vec<u8>,
    identity_hash: [u8; 32],
    envelope: Vec<u8>,
    upstream: Vec<u8>,
}

impl Fixture {
    pub fn new() -> Self {
        let actual_aaid_hash = hash_bytes(HashDomain::Aaid, AAID);
        let (identity, identity_hash) = identity();
        let envelope = envelope(identity_hash, actual_aaid_hash, CANDIDATE_NONCE, CSR);
        Self {
            identity,
            identity_hash,
            envelope,
            upstream: standard_upstream(),
        }
    }

    pub const fn alias(&self) -> [u8; 16] {
        ALIAS
    }

    pub const fn policy(&self) -> PairedPolicy {
        PairedPolicy::new(PEER, PROFILE, PROFILE_EPOCH, self.identity_hash)
    }

    pub fn generate(&self, request: u8) -> GenerateRequest<'_> {
        self.generate_parts(request, self.context(), &self.envelope, &self.upstream, CSR)
    }

    pub fn generate_with_epoch(&self, request: u8, epoch: u64) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.profile_epoch = epoch;
        self.generate_parts(request, context, &self.envelope, &self.upstream, CSR)
    }

    pub fn generate_at(&self, request: u8, now_ms: u64) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.now_ms = now_ms;
        self.generate_parts(request, context, &self.envelope, &self.upstream, CSR)
    }

    pub fn generate_with_peer(&self, request: u8, peer: [u8; 32]) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.peer_spki_hash = peer;
        self.generate_parts(request, context, &self.envelope, &self.upstream, CSR)
    }

    pub fn generate_with_nonce(&self, request: u8, nonce: [u8; 32]) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.candidate_nonce = nonce;
        self.generate_parts(request, context, &self.envelope, &self.upstream, CSR)
    }

    pub fn generate_with_upstream_envelope(&self, request: u8) -> GenerateRequest<'_> {
        self.generate_parts(request, self.context(), &self.envelope, &self.envelope, CSR)
    }

    pub fn generate_with_broken_csr_hash(&self, request: u8) -> GenerateRequest<'_> {
        self.generate_parts(
            request,
            self.context(),
            &self.envelope,
            &self.upstream,
            [0xfe; 32],
        )
    }

    pub fn begin(&self, request: u8) -> BeginRequest {
        BeginRequest::new(request_id(request), self.context(), ALIAS)
    }

    pub fn begin_with_identity(&self, request: u8, identity_hash: [u8; 32]) -> BeginRequest {
        let mut context = self.context();
        context.candidate_identity_hash = identity_hash;
        BeginRequest::new(request_id(request), context, ALIAS)
    }

    pub fn abort(&self, request: u8, operation: RemoteOperationHandle) -> OperationRequest<'_> {
        OperationRequest::new(request_id(request), self.context(), ALIAS, operation, &[])
    }

    pub fn update<'a>(
        &self,
        request: u8,
        operation: RemoteOperationHandle,
        input: &'a [u8],
    ) -> OperationRequest<'a> {
        OperationRequest::new(request_id(request), self.context(), ALIAS, operation, input)
    }

    pub fn finish(&self, request: u8, operation: RemoteOperationHandle) -> FinishRequest<'_> {
        FinishRequest::new(OperationRequest::new(
            request_id(request),
            self.context(),
            ALIAS,
            operation,
            &[],
        ))
    }

    pub fn get(&self, request: u8) -> DeleteRequest {
        DeleteRequest::new(request_id(request), self.context(), ALIAS)
    }

    pub fn delete(&self, request: u8) -> DeleteRequest {
        self.get(request)
    }

    const fn context(&self) -> AccessContext {
        AccessContext {
            peer_spki_hash: PEER,
            profile_id_hash: PROFILE,
            profile_epoch: PROFILE_EPOCH,
            session_id: SESSION,
            candidate_nonce: CANDIDATE_NONCE,
            donor_nonce: DONOR_NONCE,
            candidate_identity_hash: self.identity_hash,
            now_ms: 1,
        }
    }

    fn generate_parts<'a>(
        &'a self,
        request: u8,
        context: AccessContext,
        envelope: &'a [u8],
        upstream: &'a [u8],
        csr_hash: [u8; 32],
    ) -> GenerateRequest<'a> {
        GenerateRequest::new(
            request_id(request),
            context,
            ALIAS,
            &self.identity,
            &self.identity,
            envelope,
            upstream,
            RemoteKeyHandle::new([0xb1; 32]),
            b"0123456789abcdef",
            [0xc1; 32],
            [RKP_PUBLIC].as_slice(),
            csr_hash,
            SERVER_BODY,
            CHALLENGE,
            RESPONSE,
            CHAIN,
        )
    }
}

#[derive(Debug, Default)]
pub struct FakeBroker {
    pub generated_requests: usize,
    pub abort_calls: usize,
    pub finish_calls: usize,
    pub delete_calls: usize,
}

impl DonorBroker for FakeBroker {
    fn generate(&mut self, request: BrokerGenerate<'_>) -> Result<GeneratedKey, BrokerFailure> {
        self.generated_requests += 1;
        assert_eq!(request.rkp_handle, RemoteKeyHandle::new([0xb1; 32]));
        assert_ne!(request.envelope_hash, [0; 32]);
        Ok(GeneratedKey::new(
            RemoteKeyHandle::new([0xd1; 32]),
            vec![b"leaf".to_vec(), b"root".to_vec()],
            [0xd2; 32],
            [0xd3; 32],
        ))
    }

    fn begin(&mut self, _request: BrokerBegin) -> Result<RemoteOperationHandle, BrokerFailure> {
        Ok(RemoteOperationHandle::new([0xe1; 16]))
    }

    fn update_aad(
        &mut self,
        _operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<usize, BrokerFailure> {
        Ok(input.len())
    }

    fn update(
        &mut self,
        _operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        Ok(input.to_vec())
    }

    fn finish(
        &mut self,
        _operation: RemoteOperationHandle,
        _input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        self.finish_calls += 1;
        Ok(vec![0x30, 0x01, 0x01])
    }

    fn abort(&mut self, _operation: RemoteOperationHandle) -> Result<(), BrokerFailure> {
        self.abort_calls += 1;
        Ok(())
    }

    fn delete(&mut self, _key: RemoteKeyHandle) -> Result<(), BrokerFailure> {
        self.delete_calls += 1;
        Ok(())
    }

    fn get(&mut self, _key: RemoteKeyHandle) -> Result<PublicKeyResult, BrokerFailure> {
        Err(BrokerFailure::Unavailable)
    }
}

const fn request_id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn identity() -> (Vec<u8>, [u8; 32]) {
    let mut unsigned = CborWriter::with_capacity(256);
    encode_identity_prefix(&mut unsigned, 5);
    unsigned.unsigned(5);
    unsigned.bytes(&LINEAGE_HASH);
    let identity_hash = hash_cbor(HashDomain::Identity, &unsigned.finish());
    let mut writer = CborWriter::with_capacity(256);
    encode_identity_prefix(&mut writer, 6);
    writer.unsigned(4);
    writer.bytes(&identity_hash);
    writer.unsigned(5);
    writer.bytes(&LINEAGE_HASH);
    (writer.finish(), identity_hash)
}

fn encode_identity_prefix(writer: &mut CborWriter, map_size: usize) {
    writer.map(map_size);
    writer.unsigned(0);
    writer.unsigned(0);
    writer.unsigned(1);
    writer.unsigned(10_001);
    writer.unsigned(2);
    writer.array(1);
    writer.array(3);
    writer.text("com.example.candidate");
    writer.unsigned(1);
    writer.array(1);
    writer.bytes(b"signer");
    writer.unsigned(3);
    writer.bytes(AAID);
}

fn envelope(
    identity_hash: [u8; 32],
    aaid_hash: [u8; 32],
    nonce: [u8; 32],
    csr: [u8; 32],
) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(512);
    writer.map(17);
    for (key, value) in [(0, None), (1, Some(identity_hash)), (2, Some(aaid_hash))] {
        writer.unsigned(key);
        if let Some(bytes) = value {
            writer.bytes(&bytes);
        } else {
            writer.unsigned(1);
        }
    }
    writer.unsigned(3);
    writer.unsigned(PROFILE_EPOCH);
    for (key, value) in [(4, nonce), (5, DONOR_NONCE), (6, IRPC)] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(7);
    writer.array(1);
    writer.bytes(&RKP_PUBLIC);
    for (key, value) in [
        (8, csr),
        (9, SERVER_BODY),
        (10, CHALLENGE),
        (11, RESPONSE),
        (12, CHAIN),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(13);
    writer.unsigned(0);
    writer.unsigned(14);
    writer.unsigned(120);
    writer.unsigned(15);
    writer.unsigned(1);
    writer.unsigned(16);
    writer.unsigned(0);
    writer.finish()
}

fn standard_upstream() -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(8);
    writer.map(1);
    writer.unsigned(0);
    writer.unsigned(1);
    writer.finish()
}
