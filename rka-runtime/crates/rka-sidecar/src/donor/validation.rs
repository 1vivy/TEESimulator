use rka_protocol::{
    HashDomain, decode_candidate_identity, decode_envelope, hash_bytes, validate_upstream_rkp_bytes,
};

use super::{AccessContext, DonorError, GenerateRequest, PairedPolicy};

pub(super) struct ValidatedGenerate<'a> {
    pub aaid: &'a [u8],
    pub envelope_hash: [u8; 32],
    pub started_ms: u64,
}

pub(super) fn authorize(policy: PairedPolicy, context: AccessContext) -> Result<(), DonorError> {
    if context.peer_spki_hash != policy.peer_spki_hash
        || context.profile_id_hash != policy.profile_id_hash
    {
        return Err(DonorError::Unpaired);
    }
    if context.profile_epoch != policy.profile_epoch {
        return Err(DonorError::StaleProfile);
    }
    if context.candidate_identity_hash != policy.candidate_identity_hash {
        return Err(DonorError::IdentityDrift);
    }
    Ok(())
}

pub(super) fn validate_generate<'a>(
    policy: PairedPolicy,
    request: &GenerateRequest<'a>,
) -> Result<ValidatedGenerate<'a>, DonorError> {
    authorize(policy, request.context)?;
    let candidate = decode_candidate_identity(request.candidate_identity)
        .map_err(|_| DonorError::IdentityDrift)?;
    let authoritative = decode_candidate_identity(request.authoritative_identity)
        .map_err(|_| DonorError::IdentityDrift)?;
    if candidate != authoritative {
        return Err(DonorError::IdentityDrift);
    }
    if candidate.identity_hash != policy.candidate_identity_hash
        || candidate.identity_hash != request.context.candidate_identity_hash
    {
        return Err(DonorError::IdentityDrift);
    }
    let envelope = decode_envelope(request.envelope).map_err(|_| DonorError::EnvelopeMismatch)?;
    let phase_hashes = [
        envelope.hal_csr_hash,
        envelope.server_body_hash,
        envelope.server_challenge_hash,
        envelope.server_response_hash,
        envelope.validated_chain_set_hash,
    ];
    let expected_phases = request.phase_hashes.map(Some);
    let aaid_hash = hash_bytes(HashDomain::Aaid, authoritative.aaid_der);
    if envelope.candidate_identity_hash != candidate.identity_hash
        || envelope.aaid_hash != aaid_hash
        || envelope.profile_epoch != request.context.profile_epoch
        || envelope.candidate_nonce != request.context.candidate_nonce
        || envelope.donor_nonce != request.context.donor_nonce
        || envelope.ordered_rkp_public_hashes.as_deref() != Some(request.ordered_rkp_public_hashes)
        || phase_hashes != expected_phases
        || envelope.successful_finish_count != 0
    {
        return Err(DonorError::EnvelopeMismatch);
    }
    if envelope.donor_irpc_identity_hash != policy.donor_irpc_identity_hash {
        return Err(DonorError::IrpcIdentityMismatch);
    }
    if request.prior_transcript_hash != request.expected_prior_transcript_hash {
        return Err(DonorError::TranscriptMismatch);
    }
    let expires = envelope
        .donor_monotonic_start_ms
        .checked_add(rka_protocol::TTL_SECONDS.saturating_mul(1_000))
        .ok_or(DonorError::Expired)?;
    if request.context.now_ms > expires {
        return Err(DonorError::Expired);
    }
    validate_upstream_rkp_bytes(request.upstream_body, request.envelope)
        .map_err(|_| DonorError::EnvelopeUpstream)?;
    Ok(ValidatedGenerate {
        aaid: authoritative.aaid_der,
        envelope_hash: hash_bytes(HashDomain::Envelope, request.envelope),
        started_ms: envelope.donor_monotonic_start_ms,
    })
}
