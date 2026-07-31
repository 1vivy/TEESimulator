use rka_protocol::{
    Frame, FrameBody, FrameContext, MessageKind, RequestId, decode_frame, encode_frame,
    encode_frame_without_transcript, transcript_hash,
};

use super::{
    AccessContext, BeginRequest, DeleteRequest, DonorError, DonorRuntime, FinishRequest,
    GenerateCoordinates, GenerateEvidence, GenerateKeyMaterial, GenerateRequest, OperationRequest,
    RemoteOperationHandle, RkpKeyHandle,
    dispatch_codec::{
        begin_result, boolean_result, encode_envelope, encode_identity, finish_result,
        generate_result, update_result,
    },
};
use crate::provisioning_io::{FileStateStore, load_lease_chain};

pub(super) fn dispatch(runtime: &mut DonorRuntime, encoded: &[u8]) -> Result<Vec<u8>, DonorError> {
    let frame = decode_frame(encoded).map_err(|_| DonorError::InvalidFrame)?;
    let trust = runtime.trust.as_ref().ok_or(DonorError::Unpaired)?;
    if frame.profile_epoch != trust.pair.profile_epoch
        || frame.session_id.bytes() != trust.pair.session_id
    {
        return Err(DonorError::Unpaired);
    }
    let previous = trust.pair.prior_transcript_hash;
    let expected = transcript_hash(&previous, &encode_frame_without_transcript(&frame));
    if frame.transcript_hash != expected {
        return Err(DonorError::TranscriptMismatch);
    }
    let body = dispatch_body(runtime, &frame, previous)?;
    let trust = runtime.trust.as_mut().ok_or(DonorError::Unpaired)?;
    trust.pair.prior_transcript_hash = frame.transcript_hash;
    let root = runtime.state_root.as_deref().ok_or(DonorError::Storage)?;
    trust
        .pair
        .persist(&FileStateStore::new(root))
        .map_err(|_| DonorError::Storage)?;
    let mut response = Frame::new(
        FrameContext::new(
            (frame.request_id, frame.session_id),
            (frame.profile_epoch, frame.sequence.saturating_add(1)),
        ),
        MessageKind::Result,
        FrameBody::Response(&body),
    );
    response.transcript_hash = transcript_hash(
        &frame.transcript_hash,
        &encode_frame_without_transcript(&response),
    );
    Ok(encode_frame(&response))
}

fn dispatch_body(
    runtime: &mut DonorRuntime,
    frame: &Frame<'_>,
    previous: [u8; 32],
) -> Result<Vec<u8>, DonorError> {
    let context = access_context(runtime, frame)?;
    match &frame.body {
        FrameBody::Generate {
            identity,
            request,
            envelope,
            encoded: _,
        } => generate(
            runtime,
            frame.request_id,
            context,
            identity,
            request,
            envelope,
            previous,
        ),
        FrameBody::Begin(alias) => {
            let result =
                runtime.begin(BeginRequest::new(frame.request_id.bytes(), context, *alias))?;
            Ok(begin_result(result.operation_handle.as_array()))
        }
        FrameBody::Chunk {
            operation_handle,
            chunk,
        } if frame.kind == MessageKind::UpdateAad || frame.kind == MessageKind::Update => {
            let operation = RemoteOperationHandle::new(*operation_handle);
            let alias = runtime
                .service
                .as_ref()
                .and_then(|service| service.operation_owner(operation))
                .ok_or(DonorError::StaleHandle)?;
            let request =
                OperationRequest::new(frame.request_id.bytes(), context, alias, operation, chunk);
            let (consumed, output) = if frame.kind == MessageKind::UpdateAad {
                (runtime.update_aad(request)?, Vec::new())
            } else {
                let output = runtime.update(request)?;
                (chunk.len(), output)
            };
            Ok(update_result(frame.kind, consumed, &output))
        }
        FrameBody::Finish {
            operation_handle,
            final_input,
        } => {
            let operation = RemoteOperationHandle::new(*operation_handle);
            let alias = runtime
                .service
                .as_ref()
                .and_then(|service| service.operation_owner(operation))
                .ok_or(DonorError::StaleHandle)?;
            let result = runtime.finish(FinishRequest::new(OperationRequest::new(
                frame.request_id.bytes(),
                context,
                alias,
                operation,
                final_input,
            )))?;
            Ok(finish_result(&result.signature))
        }
        FrameBody::Handle(handle) if frame.kind == MessageKind::Abort => {
            let operation = RemoteOperationHandle::new(*handle);
            let alias = runtime
                .service
                .as_ref()
                .and_then(|service| service.operation_owner(operation))
                .ok_or(DonorError::StaleHandle)?;
            runtime.abort(OperationRequest::new(
                frame.request_id.bytes(),
                context,
                alias,
                operation,
                &[],
            ))?;
            Ok(boolean_result(MessageKind::Abort))
        }
        FrameBody::Handle(alias) if frame.kind == MessageKind::Delete => {
            runtime.delete(DeleteRequest::new(
                frame.request_id.bytes(),
                context,
                *alias,
            ))?;
            Ok(boolean_result(MessageKind::Delete))
        }
        _ => Err(DonorError::InvalidFrame),
    }
}

fn generate(
    runtime: &mut DonorRuntime,
    request_id: RequestId,
    mut context: AccessContext,
    identity: &rka_protocol::CandidateIdentity<'_>,
    request: &rka_protocol::ForegroundRequest<'_>,
    envelope: &rka_protocol::Envelope<'_>,
    previous: [u8; 32],
) -> Result<Vec<u8>, DonorError> {
    context.candidate_identity_hash = identity.identity_hash;
    let identity_bytes = encode_identity(identity);
    let envelope_bytes = encode_envelope(envelope)?;
    let trust = runtime.trust.as_ref().ok_or(DonorError::Unpaired)?;
    let ordered = trust
        .leases
        .iter()
        .map(|lease| *lease.public_key_hash.as_bytes())
        .collect::<Vec<_>>();
    if envelope.ordered_rkp_public_hashes.as_deref() != Some(ordered.as_slice()) {
        return Err(DonorError::EnvelopeMismatch);
    }
    let lease = trust.leases.first().ok_or(DonorError::Unpaired)?;
    let root = runtime.state_root.as_deref().ok_or(DonorError::Storage)?;
    let chain =
        load_lease_chain(root, lease.remote_handle.as_bytes()).map_err(|_| DonorError::Storage)?;
    let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let phase_hashes = lease.phase_hashes;
    runtime.generate(GenerateRequest::new(
        GenerateCoordinates {
            request_id: request_id.bytes(),
            context,
            alias: request.alias_handle,
        },
        GenerateEvidence {
            candidate_identity: &identity_bytes,
            envelope: &envelope_bytes,
            upstream_body: &[],
            ordered_rkp_public_hashes: &ordered,
            phase_hashes,
        },
        GenerateKeyMaterial {
            rkp_handle: RkpKeyHandle::new(*lease.remote_handle.as_bytes()),
            rkp_chain: &chain_refs,
            challenge: request.attestation_challenge,
            prior_transcript_hash: previous,
        },
    ))?;
    let public = runtime
        .service
        .as_ref()
        .and_then(|service| service.public_for_alias(request.alias_handle))
        .ok_or(DonorError::Broker)?;
    Ok(generate_result(
        request.alias_handle,
        public,
        &envelope_bytes,
        envelope,
        request.attestation_challenge,
    ))
}

fn access_context(runtime: &DonorRuntime, frame: &Frame<'_>) -> Result<AccessContext, DonorError> {
    let pair = runtime
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
