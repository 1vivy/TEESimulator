use rka_sidecar::donor::{
    AccessContext, GenerateCoordinates, GenerateEvidence, GenerateKeyMaterial, GenerateRequest,
    RkpKeyHandle,
};

use super::{
    encoding::{
        ALIAS, CHAIN, CHALLENGE, CSR, RESPONSE, RKP_CHAIN, RKP_PUBLIC, SERVER_BODY, request_id,
    },
    fixture::Fixture,
};

impl Fixture {
    pub fn generate(&self, request: u8) -> GenerateRequest<'_> {
        self.generate_parts(
            request,
            self.context(),
            ALIAS,
            &self.envelope,
            CSR,
            [0xc1; 32],
        )
    }

    pub fn generate_with_alias(&self, request: u8, alias: [u8; 16]) -> GenerateRequest<'_> {
        self.generate_parts(
            request,
            self.context(),
            alias,
            &self.envelope,
            CSR,
            [0xc1; 32],
        )
    }

    pub fn generate_secondary(&self, request: u8) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.candidate_nonce = [0x34; 32];
        self.generate_parts(
            request,
            context,
            [0xa2; 16],
            &self.secondary_envelope,
            CSR,
            [0xc1; 32],
        )
    }

    pub fn generate_with_epoch(&self, request: u8, epoch: u64) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.profile_epoch = epoch;
        self.generate_parts(request, context, ALIAS, &self.envelope, CSR, [0xc1; 32])
    }

    pub fn generate_at(&self, request: u8, now_ms: u64) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.now_ms = now_ms;
        self.generate_parts(request, context, ALIAS, &self.envelope, CSR, [0xc1; 32])
    }

    pub fn generate_with_peer(&self, request: u8, peer: [u8; 32]) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.peer_spki_hash = peer;
        self.generate_parts(request, context, ALIAS, &self.envelope, CSR, [0xc1; 32])
    }

    pub fn generate_with_nonce(&self, request: u8, nonce: [u8; 32]) -> GenerateRequest<'_> {
        let mut context = self.context();
        context.candidate_nonce = nonce;
        self.generate_parts(request, context, ALIAS, &self.envelope, CSR, [0xc1; 32])
    }

    pub fn generate_with_broken_csr_hash(&self, request: u8) -> GenerateRequest<'_> {
        self.generate_parts(
            request,
            self.context(),
            ALIAS,
            &self.envelope,
            [0xfe; 32],
            [0xc1; 32],
        )
    }

    pub fn generate_with_irpc(&self, request: u8, irpc: [u8; 32]) -> GenerateRequest<'_> {
        assert_eq!(irpc, [0xfa; 32]);
        self.generate_parts(
            request,
            self.context(),
            ALIAS,
            &self.mismatched_irpc_envelope,
            CSR,
            [0xc1; 32],
        )
    }

    pub fn generate_with_transcript(
        &self,
        request: u8,
        transcript: [u8; 32],
    ) -> GenerateRequest<'_> {
        self.generate_parts(
            request,
            self.context(),
            ALIAS,
            &self.envelope,
            CSR,
            transcript,
        )
    }

    fn generate_parts<'a>(
        &'a self,
        request: u8,
        context: AccessContext,
        alias: [u8; 16],
        envelope: &'a [u8],
        csr_hash: [u8; 32],
        transcript: [u8; 32],
    ) -> GenerateRequest<'a> {
        GenerateRequest::new(
            GenerateCoordinates {
                request_id: request_id(request),
                context,
                alias,
            },
            GenerateEvidence {
                candidate_identity: &self.identity,
                envelope,
                ordered_rkp_public_hashes: [RKP_PUBLIC].as_slice(),
                phase_hashes: [csr_hash, SERVER_BODY, CHALLENGE, RESPONSE, CHAIN],
            },
            GenerateKeyMaterial {
                rkp_handle: RkpKeyHandle::new([0xb1; 32]),
                rkp_chain: &RKP_CHAIN,
                challenge: b"0123456789abcdef",
                prior_transcript_hash: transcript,
            },
        )
    }
}
