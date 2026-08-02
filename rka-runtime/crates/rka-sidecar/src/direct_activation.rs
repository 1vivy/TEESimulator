//! Durable admission binding for one directly paired donor and candidate.

use std::{env, fs, path::Path};

use ring::digest::{Context, SHA256};
use rka_state::PairedActivationRecord;

use crate::{LifecycleRole, direct_profile, provisioning_io::FileStateStore};

const IDENTITY_MARKER: &str = "trust/transport-identity.commit";
const MAX_TRANSACTION_BYTES: usize = 128;

/// Persists the shared admission record before either direct runtime is started.
pub fn activate(role: LifecycleRole) -> Result<String, &'static str> {
    let transaction = env::var("RKA_PAIR_TRANSACTION_ID").map_err(|_| "invalid_context")?;
    if transaction.is_empty()
        || transaction.len() > MAX_TRANSACTION_BYTES
        || !transaction
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid_context");
    }
    let (state, profile, _) = direct_profile::load(role).map_err(|_| "invalid_context")?;
    let own_pin = identity_pin(&state)?;
    let (donor_pin, candidate_pin) = match role {
        LifecycleRole::Donor => (own_pin, profile.peer_pin),
        LifecycleRole::Candidate => (profile.peer_pin, own_pin),
    };
    let epoch = profile.epoch.to_be_bytes();
    let binding = [transaction.as_bytes(), &donor_pin, &candidate_pin, &epoch];
    PairedActivationRecord {
        peer_spki_hash: profile.peer_pin,
        profile_id_hash: derive(b"profile", &binding),
        profile_epoch: profile.epoch,
        candidate_identity_hash: derive(b"candidate-transport", &[&candidate_pin]),
        session_id: derive(b"session", &binding),
        candidate_nonce: derive(b"candidate-nonce", &binding),
        donor_nonce: derive(b"donor-nonce", &binding),
        prior_transcript_hash: derive(b"transcript", &binding),
    }
    .persist(&FileStateStore::new(&state))
    .map_err(|_| "persist_failed")?;
    Ok(format!(
        "RESULT=ACTIVATED profile_epoch={}\n",
        profile.epoch
    ))
}

fn identity_pin(state: &Path) -> Result<[u8; 32], &'static str> {
    let marker = fs::read_to_string(state.join(IDENTITY_MARKER)).map_err(|_| "invalid_context")?;
    let encoded = marker
        .strip_prefix("version=1\nspki_sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or("invalid_context")?;
    decode_hash(encoded)
}

fn decode_hash(encoded: &str) -> Result<[u8; 32], &'static str> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid_context");
    }
    let mut decoded = [0_u8; 32];
    for (destination, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid_context")?;
        *destination = u8::from_str_radix(text, 16).map_err(|_| "invalid_context")?;
    }
    Ok(decoded)
}

fn derive(label: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut digest = Context::new(&SHA256);
    digest.update(b"TEESimulator-RS direct activation v1\0");
    digest.update(label);
    for field in fields {
        digest.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(field);
    }
    let mut value = [0_u8; 32];
    value.copy_from_slice(digest.finish().as_ref());
    value
}
