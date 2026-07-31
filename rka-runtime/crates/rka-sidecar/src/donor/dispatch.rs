use rka_protocol::{
    Frame, FrameBody, FrameContext, HashDomain, MessageKind, RequestId, decode_frame, encode_frame,
    encode_frame_without_transcript, hash_bytes, transcript_hash,
};

use super::{
    AccessContext, BeginRequest, DeleteRequest, DonorError, DonorRuntime, FinishRequest,
    GenerateCoordinates, GenerateEvidence, GenerateKeyMaterial, GenerateRequest, OperationRequest,
    RemoteOperationHandle, RkpKeyHandle,
    dispatch_codec::{
        begin_result, boolean_result, encode_envelope, encode_identity, finish_result,
        generate_result, update_result,
    },
    lease::load_verified_chain,
    state::PendingTranscript,
};

pub(super) fn dispatch(runtime: &mut DonorRuntime, encoded: &[u8]) -> Result<Vec<u8>, DonorError> {
    let frame = decode_frame(encoded).map_err(|_| DonorError::InvalidFrame)?;
    let trust = runtime.trust.as_ref().ok_or(DonorError::Unpaired)?;
    if frame.profile_epoch != trust.pair.profile_epoch
        || frame.session_id.bytes() != trust.pair.session_id
    {
        return Err(DonorError::Unpaired);
    }
    let previous = runtime
        .transcript
        .as_ref()
        .ok_or(DonorError::Unpaired)?
        .committed()?;
    let canonical_request = encode_frame_without_transcript(&frame);
    let expected = transcript_hash(&previous, &canonical_request);
    if frame.transcript_hash != expected {
        return Err(DonorError::TranscriptMismatch);
    }
    super::dispatch_preflight::preflight(runtime, &frame, previous)?;
    runtime
        .transcript
        .as_mut()
        .ok_or(DonorError::Unpaired)?
        .reserve(PendingTranscript {
            prior: previous,
            request_hash: hash_bytes(HashDomain::Frame, &canonical_request),
            next: expected,
            peer: trust.pair.peer_spki_hash,
            epoch: frame.profile_epoch,
            session: frame.session_id.bytes(),
            request_id: frame.request_id.bytes(),
        })?;
    let body = dispatch_body(runtime, &frame, previous)?;
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
    runtime
        .transcript
        .as_mut()
        .ok_or(DonorError::Unpaired)?
        .commit_result(frame.transcript_hash, response.transcript_hash)?;
    Ok(encode_frame(&response))
}

fn dispatch_body(
    runtime: &mut DonorRuntime,
    frame: &Frame<'_>,
    previous: [u8; 32],
) -> Result<Vec<u8>, DonorError> {
    let context = super::dispatch_preflight::access_context(runtime, frame)?;
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
    let chain = load_verified_chain(root, lease)?;
    let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
    runtime.generate(GenerateRequest::new(
        GenerateCoordinates {
            request_id: request_id.bytes(),
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
