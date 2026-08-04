use rka_protocol::{HashDomain, hash_bytes};
use rka_sidecar::donor::{
    AccessContext, BeginRequest, DeleteRequest, FinishRequest, OperationRequest, PairedPolicy,
    RemoteOperationHandle,
};

use super::encoding::{
    AAID, ALIAS, CANDIDATE_NONCE, CSR, DONOR_NONCE, IRPC, PEER, PEER_B, PROFILE, PROFILE_B,
    PROFILE_EPOCH, SESSION, envelope, identity, identity_b, request_id,
};

#[derive(Debug)]
pub struct Fixture {
    pub(super) identity: Vec<u8>,
    identity_hash: [u8; 32],
    peer_spki_hash: [u8; 32],
    profile_id_hash: [u8; 32],
    pub(super) envelope: Vec<u8>,
    pub(super) secondary_envelope: Vec<u8>,
    pub(super) mismatched_irpc_envelope: Vec<u8>,
}

impl Fixture {
    pub fn new() -> Self {
        Self::for_candidate(PEER, PROFILE, identity())
    }

    pub fn candidate_b() -> Self {
        Self::for_candidate(PEER_B, PROFILE_B, identity_b())
    }

    fn for_candidate(
        peer_spki_hash: [u8; 32],
        profile_id_hash: [u8; 32],
        (identity, identity_hash): (Vec<u8>, [u8; 32]),
    ) -> Self {
        let actual_aaid_hash = hash_bytes(HashDomain::Aaid, AAID);
        Self {
            identity,
            identity_hash,
            peer_spki_hash,
            profile_id_hash,
            envelope: envelope(identity_hash, actual_aaid_hash, CANDIDATE_NONCE, CSR, IRPC),
            secondary_envelope: envelope(identity_hash, actual_aaid_hash, [0x34; 32], CSR, IRPC),
            mismatched_irpc_envelope: envelope(
                identity_hash,
                actual_aaid_hash,
                CANDIDATE_NONCE,
                CSR,
                [0xfa; 32],
            ),
        }
    }

    pub const fn alias(&self) -> [u8; 16] {
        ALIAS
    }

    pub const fn policy(&self) -> PairedPolicy {
        PairedPolicy::new(
            self.peer_spki_hash,
            self.profile_id_hash,
            PROFILE_EPOCH,
            self.identity_hash,
            IRPC,
            [0xc1; 32],
        )
    }

    pub const fn policy_identity_material(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            self.peer_spki_hash,
            self.profile_id_hash,
            self.identity_hash,
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
            peer_spki_hash: self.peer_spki_hash,
            profile_id_hash: self.profile_id_hash,
            profile_epoch: PROFILE_EPOCH,
            session_id: SESSION,
            candidate_nonce: CANDIDATE_NONCE,
            donor_nonce: DONOR_NONCE,
            candidate_identity_hash: self.identity_hash,
            now_ms: 1,
        }
    }
}
