//! Root-only, one-shot donor capability probe for an imported synthetic RKP lease.

use std::{
    env, fmt,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ring::{
    digest::{Context, SHA256, digest},
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use rka_state::RkpLeaseBatch;
use x509_parser::parse_x509_certificate;

use crate::{
    bridge::{
        BridgeMessage, BrokerOperation, Hash32, PublicBytes, RequestId, RoleExecutor, SecretBytes,
        SidecarRole,
    },
    provisioning_io::{FileStateStore, load_lease_chain},
};

const PROBE_BUDGET: Duration = Duration::from_secs(30);
const MAX_CERTIFICATE_BYTES: usize = 65_536;
const MAX_PKCS8_BYTES: usize = 4_096;
const MAX_AAID_BYTES: usize = 131_072;
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const AAID_DOMAIN: &[u8] = b"TEESimulator-RS synthetic RKP lease probe v1";

/// Stable, secret-free probe failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyntheticLeaseProbeStatus {
    /// The command was not launched by root with exact private runtime paths.
    InvalidContext,
    /// No single certified donor RKP lease was available.
    StateUnavailable,
    /// Ephemeral EC P-256 material could not be created.
    KeyGenerationFailed,
    /// The authenticated broker exchange did not complete.
    BrokerFailed,
    /// The broker returned a noncanonical or cryptographically invalid chain.
    ResponseRejected,
}

impl fmt::Display for SyntheticLeaseProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContext => "invalid_context",
            Self::StateUnavailable => "state_unavailable",
            Self::KeyGenerationFailed => "key_generation_failed",
            Self::BrokerFailed => "broker_failed",
            Self::ResponseRejected => "response_rejected",
        })
    }
}

/// Public-only proof that the donor imported, certified, validated, and deleted the probe key.
#[derive(Debug, Eq, PartialEq)]
pub struct SyntheticLeaseProbeReceipt {
    certificate_count: usize,
    spki_hash: [u8; 32],
    chain_hash: [u8; 32],
    leaf_ca: bool,
    leaf_key_cert_sign: bool,
}

impl fmt::Display for SyntheticLeaseProbeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "synthetic_lease_probe_status=READY certificate_count={} spki_sha256={} chain_sha256={} leaf_ca={} leaf_key_cert_sign={}",
            self.certificate_count,
            hex(&self.spki_hash),
            hex(&self.chain_hash),
            self.leaf_ca,
            self.leaf_key_cert_sign,
        )
    }
}

/// Executes one bounded same-device import probe against the active donor RKP lease.
pub fn probe() -> Result<SyntheticLeaseProbeReceipt, SyntheticLeaseProbeStatus> {
    let state_root = required_absolute_path("RKA_STATE_ROOT")?;
    let broker_socket = required_absolute_path("RKA_DONOR_SOCKET")?;
    if !rustix::process::geteuid().is_root() {
        return Err(SyntheticLeaseProbeStatus::InvalidContext);
    }

    let batch = RkpLeaseBatch::load_active(&FileStateStore::new(&state_root))
        .map_err(|_| SyntheticLeaseProbeStatus::StateUnavailable)?;
    let [lease] = batch.leases() else {
        return Err(SyntheticLeaseProbeStatus::StateUnavailable);
    };
    let metadata = lease.metadata();
    let donor_chain = load_lease_chain(&state_root, metadata.remote_handle.as_bytes())
        .map_err(|_| SyntheticLeaseProbeStatus::StateUnavailable)?;
    if donor_chain.len() != usize::from(metadata.chain.certificate_count) {
        return Err(SyntheticLeaseProbeStatus::StateUnavailable);
    }

    let rng = SystemRandom::new();
    let key_document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_document.as_ref(), &rng)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
    let expected_spki = p256_spki(key_pair.public_key().as_ref())?;
    let mut challenge = [0_u8; 32];
    rng.fill(&mut challenge)
        .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
    let aaid = synthetic_aaid(metadata.profile_epoch);
    let request_id = fresh_request_id(&rng)?;
    let (not_before, not_after) = requested_validity()?;

    let request = BridgeMessage::SyntheticLeaseProbeRequest {
        request_id: RequestId::new(request_id),
        rkp_handle: Hash32::new(*metadata.remote_handle.as_bytes()),
        private_key_pkcs8: SecretBytes::bounded(key_document.as_ref(), MAX_PKCS8_BYTES)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?,
        expected_spki: PublicBytes::bounded(&expected_spki, 1, MAX_CERTIFICATE_BYTES)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?,
        challenge: PublicBytes::bounded(&challenge, 16, 64)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?,
        aaid: PublicBytes::bounded(&aaid, 1, MAX_AAID_BYTES)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?,
        certificate_not_before_millis: not_before,
        certificate_not_after_millis: not_after,
        certificate_chain: public_chain(&donor_chain)?,
    };

    let response = RoleExecutor::new(SidecarRole::Donor)
        .dispatch_with_budget(
            BrokerOperation::Donor {
                socket_path: &broker_socket,
                request: &request,
            },
            PROBE_BUDGET,
        )
        .map_err(|_| SyntheticLeaseProbeStatus::BrokerFailed)?;
    validate_response(response, &expected_spki, &donor_chain)
}

fn required_absolute_path(name: &str) -> Result<PathBuf, SyntheticLeaseProbeStatus> {
    let path = env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(SyntheticLeaseProbeStatus::InvalidContext)?;
    if !path.is_absolute() {
        return Err(SyntheticLeaseProbeStatus::InvalidContext);
    }
    Ok(path)
}

fn requested_validity() -> Result<(u64, u64), SyntheticLeaseProbeStatus> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SyntheticLeaseProbeStatus::InvalidContext)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| SyntheticLeaseProbeStatus::InvalidContext)?;
    let not_before = now.saturating_sub(300_000);
    let not_after = now
        .checked_add(7 * 24 * 60 * 60 * 1_000)
        .ok_or(SyntheticLeaseProbeStatus::InvalidContext)?;
    Ok((not_before, not_after))
}

fn fresh_request_id(rng: &SystemRandom) -> Result<u64, SyntheticLeaseProbeStatus> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 8];
        rng.fill(&mut bytes)
            .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
        let value = u64::from_be_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
    Err(SyntheticLeaseProbeStatus::KeyGenerationFailed)
}

fn p256_spki(point: &[u8]) -> Result<Vec<u8>, SyntheticLeaseProbeStatus> {
    if point.len() != 65 || point.first() != Some(&0x04) {
        return Err(SyntheticLeaseProbeStatus::KeyGenerationFailed);
    }
    let mut spki = Vec::new();
    let length = P256_SPKI_PREFIX
        .len()
        .checked_add(point.len())
        .ok_or(SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
    spki.try_reserve_exact(length)
        .map_err(|_| SyntheticLeaseProbeStatus::KeyGenerationFailed)?;
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.extend_from_slice(point);
    Ok(spki)
}

fn synthetic_aaid(epoch: u64) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(AAID_DOMAIN);
    context.update(&epoch.to_be_bytes());
    let mut value = [0_u8; 32];
    value.copy_from_slice(context.finish().as_ref());
    value
}

fn public_chain(chain: &[Vec<u8>]) -> Result<Vec<PublicBytes>, SyntheticLeaseProbeStatus> {
    chain
        .iter()
        .map(|certificate| {
            PublicBytes::bounded(certificate, 1, MAX_CERTIFICATE_BYTES)
                .map_err(|_| SyntheticLeaseProbeStatus::StateUnavailable)
        })
        .collect()
}

fn validate_response(
    response: BridgeMessage,
    expected_spki: &[u8],
    donor_chain: &[Vec<u8>],
) -> Result<SyntheticLeaseProbeReceipt, SyntheticLeaseProbeStatus> {
    let BridgeMessage::SyntheticLeaseProbeResponse {
        certificate_chain, ..
    } = response
    else {
        return Err(SyntheticLeaseProbeStatus::ResponseRejected);
    };
    if certificate_chain.len() != donor_chain.len().saturating_add(1)
        || !certificate_chain
            .iter()
            .skip(1)
            .zip(donor_chain)
            .all(|(actual, expected)| actual.as_slice() == expected)
    {
        return Err(SyntheticLeaseProbeStatus::ResponseRejected);
    }

    let encoded = certificate_chain
        .iter()
        .map(PublicBytes::as_slice)
        .collect::<Vec<_>>();
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(encoded.len())
        .map_err(|_| SyntheticLeaseProbeStatus::ResponseRejected)?;
    for certificate in &encoded {
        let (remaining, parsed_certificate) = parse_x509_certificate(certificate)
            .map_err(|_| SyntheticLeaseProbeStatus::ResponseRejected)?;
        if !remaining.is_empty() {
            return Err(SyntheticLeaseProbeStatus::ResponseRejected);
        }
        parsed.push(parsed_certificate);
    }
    let leaf = parsed
        .first()
        .ok_or(SyntheticLeaseProbeStatus::ResponseRejected)?;
    if leaf.tbs_certificate.subject_pki.raw != expected_spki {
        return Err(SyntheticLeaseProbeStatus::ResponseRejected);
    }
    for pair in parsed.windows(2) {
        let child = pair
            .first()
            .ok_or(SyntheticLeaseProbeStatus::ResponseRejected)?;
        let issuer = pair
            .get(1)
            .ok_or(SyntheticLeaseProbeStatus::ResponseRejected)?;
        if child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Err(SyntheticLeaseProbeStatus::ResponseRejected);
        }
    }
    let root = parsed
        .last()
        .ok_or(SyntheticLeaseProbeStatus::ResponseRejected)?;
    if root.issuer() != root.subject() || root.verify_signature(Some(root.public_key())).is_err() {
        return Err(SyntheticLeaseProbeStatus::ResponseRejected);
    }

    let leaf_ca = leaf
        .basic_constraints()
        .map_err(|_| SyntheticLeaseProbeStatus::ResponseRejected)?
        .is_some_and(|extension| extension.value.ca);
    let leaf_key_cert_sign = leaf
        .key_usage()
        .map_err(|_| SyntheticLeaseProbeStatus::ResponseRejected)?
        .is_some_and(|extension| extension.value.key_cert_sign());
    let mut chain_context = Context::new(&SHA256);
    for certificate in &encoded {
        chain_context.update(certificate);
    }
    let mut chain_hash = [0_u8; 32];
    chain_hash.copy_from_slice(chain_context.finish().as_ref());
    let mut spki_hash = [0_u8; 32];
    spki_hash.copy_from_slice(digest(&SHA256, expected_spki).as_ref());
    Ok(SyntheticLeaseProbeReceipt {
        certificate_count: encoded.len(),
        spki_hash,
        chain_hash,
        leaf_ca,
        leaf_key_cert_sign,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

const fn hex_digit(value: u8) -> char {
    match value {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        15 => 'f',
        _ => '?',
    }
}
