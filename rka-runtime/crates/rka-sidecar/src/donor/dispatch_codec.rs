use rka_protocol::{CborWriter, HashDomain, MessageKind, hash_bytes};

use super::{DonorError, PublicKeyResult};

pub(super) fn encode_identity(identity: &rka_protocol::CandidateIdentity<'_>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(256);
    writer.map(6);
    writer.unsigned(0);
    writer.unsigned(u64::from(identity.android_user));
    writer.unsigned(1);
    writer.unsigned(u64::from(identity.uid));
    writer.unsigned(2);
    writer.array(identity.packages.len());
    for package in &identity.packages {
        writer.array(3);
        writer.text(package.package_name);
        writer.unsigned(package.version_code);
        writer.array(package.current_signers.len());
        for signer in &package.current_signers {
            writer.bytes(signer);
        }
    }
    writer.unsigned(3);
    writer.bytes(identity.aaid_der);
    writer.unsigned(4);
    writer.bytes(&identity.identity_hash);
    writer.unsigned(5);
    writer.bytes(&identity.policy_lineage_hash);
    writer.finish()
}

pub(super) fn encode_envelope(
    envelope: &rka_protocol::Envelope<'_>,
) -> Result<Vec<u8>, DonorError> {
    let ordered = envelope
        .ordered_rkp_public_hashes
        .as_deref()
        .ok_or(DonorError::EnvelopeMismatch)?;
    let hashes = [
        envelope.hal_csr_hash,
        envelope.server_body_hash,
        envelope.server_challenge_hash,
        envelope.server_response_hash,
        envelope.validated_chain_set_hash,
    ]
    .map(|value| value.ok_or(DonorError::EnvelopeMismatch))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let mut writer = CborWriter::with_capacity(512);
    writer.map(17);
    writer.unsigned(0);
    writer.unsigned(1);
    for (key, value) in [
        (1, envelope.candidate_identity_hash),
        (2, envelope.aaid_hash),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(3);
    writer.unsigned(envelope.profile_epoch);
    for (key, value) in [
        (4, envelope.candidate_nonce),
        (5, envelope.donor_nonce),
        (6, envelope.donor_irpc_identity_hash),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(7);
    writer.array(ordered.len());
    for value in ordered {
        writer.bytes(value);
    }
    for (offset, value) in hashes.iter().enumerate() {
        writer.unsigned(8_u64.saturating_add(u64::try_from(offset).map_or(u64::MAX, |v| v)));
        writer.bytes(value);
    }
    writer.unsigned(13);
    writer.unsigned(envelope.donor_monotonic_start_ms);
    writer.unsigned(14);
    writer.unsigned(rka_protocol::TTL_SECONDS);
    writer.unsigned(15);
    writer.unsigned(rka_protocol::MAX_USES);
    writer.unsigned(16);
    writer.unsigned(u64::from(envelope.successful_finish_count));
    Ok(writer.finish())
}

fn result_prefix(kind: MessageKind) -> CborWriter {
    let mut writer = CborWriter::with_capacity(256);
    writer.map(2);
    writer.unsigned(0);
    writer.unsigned(kind.into());
    writer.unsigned(1);
    writer
}

pub(super) fn begin_result(operation: [u8; 16]) -> Vec<u8> {
    let mut writer = result_prefix(MessageKind::Begin);
    writer.map(2);
    writer.unsigned(0);
    writer.bytes(&operation);
    writer.unsigned(1);
    writer.unsigned(65_536);
    writer.finish()
}

pub(super) fn update_result(kind: MessageKind, consumed: usize, output: &[u8]) -> Vec<u8> {
    let mut writer = result_prefix(kind);
    writer.map(2);
    writer.unsigned(0);
    writer.unsigned(u64::try_from(consumed).unwrap_or(u64::MAX));
    writer.unsigned(1);
    writer.bytes(output);
    writer.finish()
}

pub(super) fn finish_result(signature: &[u8]) -> Vec<u8> {
    let mut writer = result_prefix(MessageKind::Finish);
    writer.map(2);
    writer.unsigned(0);
    writer.bytes(signature);
    writer.unsigned(1);
    writer.bytes(&hash_bytes(HashDomain::LeafProof, signature));
    writer.finish()
}

pub(super) fn boolean_result(kind: MessageKind) -> Vec<u8> {
    let mut writer = result_prefix(kind);
    writer.map(1);
    writer.unsigned(0);
    writer.boolean(true);
    writer.finish()
}

pub(super) fn generate_result(
    alias: [u8; 16],
    public: &PublicKeyResult,
    envelope_bytes: &[u8],
    envelope: &rka_protocol::Envelope<'_>,
    challenge: &[u8],
) -> Vec<u8> {
    let mut writer = result_prefix(MessageKind::Generate);
    writer.map(5);
    writer.unsigned(0);
    writer.bytes(&alias);
    writer.unsigned(1);
    writer.array(public.certificate_chain.len());
    for certificate in &public.certificate_chain {
        writer.bytes(certificate);
    }
    writer.unsigned(2);
    writer.bytes(&public.characteristics_hash);
    writer.unsigned(3);
    let mut result = writer.finish();
    result.extend_from_slice(envelope_bytes);
    let mut writer = CborWriter::with_capacity(256);
    writer.unsigned(4);
    writer.map(6);
    for (key, value) in [
        (0, public.leaf_spki_hash),
        (1, envelope.validated_chain_set_hash.unwrap_or([0; 32])),
        (2, hash_bytes(HashDomain::LeafProof, challenge)),
        (3, envelope.aaid_hash),
        (4, hash_bytes(HashDomain::Envelope, envelope_bytes)),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(5);
    writer.bytes(&public.transcript_signature);
    result.extend_from_slice(&writer.finish());
    result
}
