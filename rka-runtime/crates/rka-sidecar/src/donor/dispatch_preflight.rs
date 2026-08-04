use rka_protocol::{Frame, FrameBody, MessageKind};

use super::{
    AccessContext, BeginRequest, CandidateShard, DeleteRequest, DonorError, GenerateCoordinates,
    GenerateEvidence, GenerateKeyMaterial, GenerateRequest, OperationRequest,
    RemoteOperationHandle, RkpKeyHandle,
    dispatch_codec::{encode_envelope, encode_identity},
    lease::load_verified_chain,
};

pub(super) fn preflight(
    shard: &CandidateShard,
    frame: &Frame<'_>,
    previous: [u8; 32],
) -> Result<(), DonorError> {
    let context = access_context(shard, frame)?;
    let service = &shard.service;
    match &frame.body {
        FrameBody::Generate {
            identity,
            request,
            envelope,
            encoded: _,
        } => {
            let identity_bytes = encode_identity(identity);
            let envelope_bytes = encode_envelope(envelope)?;
            let trust = shard.trust.as_ref().ok_or(DonorError::Unpaired)?;
            let ordered = trust
                .leases
                .iter()
                .map(|lease| *lease.public_key_hash.as_bytes())
                .collect::<Vec<_>>();
            if envelope.ordered_rkp_public_hashes.as_deref() != Some(ordered.as_slice()) {
                return Err(DonorError::EnvelopeMismatch);
            }
            let lease = trust.leases.first().ok_or(DonorError::Unpaired)?;
            let root = shard.replay_root.as_deref().ok_or(DonorError::Storage)?;
            let chain = load_verified_chain(root, lease)?;
            let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
            service.preflight_generate(&GenerateRequest::new(
                GenerateCoordinates {
                    request_id: frame.request_id.bytes(),
                    context,
                    alias: request.alias_handle,
                },
                GenerateEvidence {
                    candidate_identity: &identity_bytes,
                    envelope: &envelope_bytes,
                    ordered_rkp_public_hashes: &ordered,
                    phase_hashes: lease.phase_hashes,
                },
                GenerateKeyMaterial {
                    rkp_handle: RkpKeyHandle::new(*lease.remote_handle.as_bytes()),
                    rkp_chain: &chain_refs,
                    challenge: request.attestation_challenge,
                    prior_transcript_hash: previous,
                },
            ))
        }
        FrameBody::Begin(alias) => {
            service.preflight_begin(BeginRequest::new(frame.request_id.bytes(), context, *alias))
        }
        FrameBody::Chunk {
            operation_handle,
            chunk,
        } if frame.kind == MessageKind::UpdateAad || frame.kind == MessageKind::Update => {
            preflight_operation(shard, frame, context, *operation_handle, chunk)
        }
        FrameBody::Finish {
            operation_handle,
            final_input,
        } => preflight_operation(shard, frame, context, *operation_handle, final_input),
        FrameBody::Handle(handle) if frame.kind == MessageKind::Abort => {
            preflight_operation(shard, frame, context, *handle, &[])
        }
        FrameBody::Handle(alias) if frame.kind == MessageKind::Delete => service.preflight_key(
            DeleteRequest::new(frame.request_id.bytes(), context, *alias),
        ),
        _ => Err(DonorError::InvalidFrame),
    }
}

fn preflight_operation(
    shard: &CandidateShard,
    frame: &Frame<'_>,
    context: AccessContext,
    operation_handle: [u8; 16],
    input: &[u8],
) -> Result<(), DonorError> {
    let operation = RemoteOperationHandle::new(operation_handle);
    let alias = shard
        .operation_owner(operation)
        .ok_or(DonorError::StaleHandle)?;
    shard.service.preflight_operation(&OperationRequest::new(
        frame.request_id.bytes(),
        context,
        alias,
        operation,
        input,
    ))
}

pub(super) fn access_context(
    shard: &CandidateShard,
    frame: &Frame<'_>,
) -> Result<AccessContext, DonorError> {
    let pair = shard
        .trust
        .as_ref()
        .map(|trust| trust.pair)
        .ok_or(DonorError::Unpaired)?;
    let uptime = std::fs::read_to_string("/proc/uptime").map_err(|_| DonorError::InvalidFrame)?;
    let value = uptime
        .split_ascii_whitespace()
        .next()
        .ok_or(DonorError::InvalidFrame)?;
    let (seconds, fraction) = value.split_once('.').ok_or(DonorError::InvalidFrame)?;
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_| DonorError::InvalidFrame)?;
    let centiseconds = fraction
        .get(..2)
        .ok_or(DonorError::InvalidFrame)?
        .parse::<u64>()
        .map_err(|_| DonorError::InvalidFrame)?;
    let now_ms = seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(centiseconds.saturating_mul(10)))
        .ok_or(DonorError::InvalidFrame)?;
    Ok(AccessContext {
        peer_spki_hash: pair.peer_spki_hash,
        profile_id_hash: pair.profile_id_hash,
        profile_epoch: pair.profile_epoch,
        session_id: frame.session_id.bytes(),
        candidate_nonce: pair.candidate_nonce,
        donor_nonce: pair.donor_nonce,
        candidate_identity_hash: pair.candidate_identity_hash,
        now_ms,
    })
}
