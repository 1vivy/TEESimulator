use rka_protocol::{HashDomain, hash_bytes};
use rka_sidecar::donor::{
    AccessContext, BeginRequest, DeleteRequest, FinishRequest, OperationRequest, PairedPolicy,
    RemoteOperationHandle,
};

use super::encoding::{
    AAID, ALIAS, CANDIDATE_NONCE, CSR, DONOR_NONCE, IRPC, PEER, PROFILE, PROFILE_EPOCH, SESSION,
    envelope, identity, request_id, standard_upstream,
};

#[derive(Debug)]
pub struct Fixture {
    pub(super) identity: Vec<u8>,
    identity_hash: [u8; 32],
    pub(super) envelope: Vec<u8>,
    pub(super) secondary_envelope: Vec<u8>,
    pub(super) mismatched_irpc_envelope: Vec<u8>,
    pub(super) upstream: Vec<u8>,
}

impl Fixture {
    pub fn new() -> Self {
        let actual_aaid_hash = hash_bytes(HashDomain::Aaid, AAID);
        let (identity, identity_hash) = identity();
        Self {
            identity,
            identity_hash,
            envelope: envelope(identity_hash, actual_aaid_hash, CANDIDATE_NONCE, CSR, IRPC),
            secondary_envelope: envelope(identity_hash, actual_aaid_hash, [0x34; 32], CSR, IRPC),
            mismatched_irpc_envelope: envelope(
                identity_hash,
                actual_aaid_hash,
                CANDIDATE_NONCE,
                CSR,
                [0xfa; 32],
            ),
            upstream: standard_upstream(),
        }
    }

    pub const fn alias(&self) -> [u8; 16] {
        ALIAS
    }

    pub const fn policy(&self) -> PairedPolicy {
        PairedPolicy::new(
            PEER,
            PROFILE,
            PROFILE_EPOCH,
            self.identity_hash,
            IRPC,
            [0xc1; 32],
        )
    }

    pub fn begin(&self, request: u8) -> BeginRequest {
        BeginRequest::new(request_id(request), self.context(), ALIAS)
    }

    pub fn begin_secondary(&self, request: u8) -> BeginRequest {
        let mut context = self.context();
        context.candidate_nonce = [0x34; 32];
        BeginRequest::new(request_id(request), context, [0xa2; 16])
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

    pub(super) const fn context(&self) -> AccessContext {
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
}
