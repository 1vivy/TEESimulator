//! Candidate-owned persistent synthetic RKP lease issuance.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ring::{
    digest::{Context, SHA256, digest},
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use rka_state::{
    MAX_SYNTHETIC_LEASE_STATE_BYTES, PairedActivationRecord, SyntheticLeaseBundle,
    SyntheticLeaseInstall, SyntheticLeaseState,
};
use rustix::process::geteuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{
    LifecycleRole,
    bridge::{
        BridgeMessage, ExchangeRole, Hash32, PublicBytes, RequestId, SecretBytes, decode_frame,
        encode_frame,
    },
    provisioning_io::{FileStateStore, atomic_replace},
};

const BUDGET: Duration = Duration::from_secs(30);
const MAX_FRAME_BYTES: usize = 1_048_576;
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Public-only receipt for one durable candidate lease installation.
#[derive(Debug, Eq, PartialEq)]
pub struct SyntheticLeaseIssueReceipt {
    slot: SyntheticLeaseInstall,
    epoch: u64,
    lease_id: [u8; 32],
    record_hash: [u8; 32],
    certificate_count: usize,
    valid_until_millis: u64,
}

impl std::fmt::Display for SyntheticLeaseIssueReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slot = match self.slot {
            SyntheticLeaseInstall::Current => "CURRENT",
            SyntheticLeaseInstall::Next => "NEXT",
            SyntheticLeaseInstall::Duplicate => "DUPLICATE",
        };
        write!(
            formatter,
            "synthetic_lease_issue_status=READY slot={slot} epoch={} lease_id={} record_sha256={} certificate_count={} valid_until_millis={}",
            self.epoch,
            hex(&self.lease_id),
            hex(&self.record_hash),
            self.certificate_count,
            self.valid_until_millis,
        )
    }
}

/// Stable, secret-free issuance error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyntheticLeaseIssueStatus {
    /// Required root-owned runtime inputs were absent or invalid.
    InvalidContext,
    /// Durable pairing or current/next state was unavailable.
    StateUnavailable,
    /// Candidate-owned EC P-256 material could not be generated.
    KeyGenerationFailed,
    /// The authenticated local/mTLS exchange failed.
    TransportFailed,
    /// The donor response failed correlation or chain validation.
    ResponseRejected,
    /// Atomic candidate state publication failed.
    PersistenceFailed,
}

impl std::fmt::Display for SyntheticLeaseIssueStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContext => "invalid_context",
            Self::StateUnavailable => "state_unavailable",
            Self::KeyGenerationFailed => "key_generation_failed",
            Self::TransportFailed => "transport_failed",
            Self::ResponseRejected => "response_rejected",
            Self::PersistenceFailed => "persistence_failed",
        })
    }
}

/// Issues and atomically stores one current or next candidate lease.
pub fn issue() -> Result<SyntheticLeaseIssueReceipt, SyntheticLeaseIssueStatus> {
    if !geteuid().is_root() {
        return Err(SyntheticLeaseIssueStatus::InvalidContext);
    }
    let (state_root, profile, _) = crate::direct_profile::load(LifecycleRole::Candidate)
        .map_err(|_| SyntheticLeaseIssueStatus::InvalidContext)?;
    let activation = PairedActivationRecord::load(&FileStateStore::new(&state_root))
        .map_err(|_| SyntheticLeaseIssueStatus::StateUnavailable)?;
    if activation.profile_epoch != profile.epoch || activation.peer_spki_hash != profile.peer_pin {
        return Err(SyntheticLeaseIssueStatus::StateUnavailable);
    }
    let now = now_millis()?;
    let state_path = state_root.join("synthetic-leases/state.bin");
    let mut state = load_state(&state_path, now)?;
    let requested_epoch = state
        .next_epoch()
        .map_err(|_| SyntheticLeaseIssueStatus::StateUnavailable)?;

    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?;
    let private_key = Zeroizing::new(document.as_ref().to_vec());
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        private_key.as_slice(),
        &rng,
    )
    .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?;
    let public_spki = p256_spki(key_pair.public_key().as_ref())?;
    let mut challenge = [0_u8; 32];
    rng.fill(&mut challenge)
        .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?;
    let aaid = synthetic_aaid(&activation.profile_id_hash, requested_epoch);
    let request_id = fresh_request_id(&rng)?;
    let not_before_millis = now.saturating_sub(300_000);
    let not_after_millis = now
        .checked_add(7 * 24 * 60 * 60 * 1_000)
        .ok_or(SyntheticLeaseIssueStatus::InvalidContext)?;
    let request = BridgeMessage::SyntheticLeaseIssueRequest {
        request_id: RequestId::new(request_id),
        candidate_nonce: Hash32::new(activation.candidate_nonce),
        profile_id_hash: Hash32::new(activation.profile_id_hash),
        requested_epoch,
        private_key_pkcs8: SecretBytes::bounded(private_key.as_slice(), 4_096)
            .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?,
        expected_spki: PublicBytes::bounded(&public_spki, 1, 65_536)
            .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?,
        challenge: PublicBytes::bounded(&challenge, 16, 64)
            .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?,
        aaid: PublicBytes::bounded(&aaid, 1, 131_072)
            .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?,
        certificate_not_before_millis: not_before_millis,
        certificate_not_after_millis: not_after_millis,
    };
    let response = exchange(&state_root.join("run/sockets/broker.sock"), &request)?;
    let chain = validate_response(response, (request_id, requested_epoch, &public_spki))?;
    let leaf_not_after_millis = leaf_not_after_millis(&chain)?;
    let effective_not_after = not_after_millis.min(leaf_not_after_millis);
    let bundle = SyntheticLeaseBundle::new(
        requested_epoch,
        activation.profile_id_hash,
        activation.peer_spki_hash,
        not_before_millis,
        effective_not_after,
        private_key.as_slice().to_vec(),
        public_spki,
        chain,
        now,
    )
    .map_err(|_| SyntheticLeaseIssueStatus::ResponseRejected)?;
    let lease_id = *bundle.lease_id();
    let certificate_count = bundle.certificate_chain().len();
    let slot = state
        .install(bundle)
        .map_err(|_| SyntheticLeaseIssueStatus::StateUnavailable)?;
    let encoded = Zeroizing::new(
        state
            .encode()
            .map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)?,
    );
    persist_state(&state_path, encoded.as_slice())?;
    let mut record_hash = [0_u8; 32];
    record_hash.copy_from_slice(digest(&SHA256, encoded.as_slice()).as_ref());
    Ok(SyntheticLeaseIssueReceipt {
        slot,
        epoch: requested_epoch,
        lease_id,
        record_hash,
        certificate_count,
        valid_until_millis: effective_not_after,
    })
}

fn load_state(
    path: &Path,
    now_millis: u64,
) -> Result<SyntheticLeaseState, SyntheticLeaseIssueStatus> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() <= MAX_SYNTHETIC_LEASE_STATE_BYTES as u64 =>
        {
            let encoded = Zeroizing::new(
                fs::read(path).map_err(|_| SyntheticLeaseIssueStatus::StateUnavailable)?,
            );
            SyntheticLeaseState::decode(encoded.as_slice(), now_millis)
                .map_err(|_| SyntheticLeaseIssueStatus::StateUnavailable)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(SyntheticLeaseState::empty())
        }
        Ok(_) | Err(_) => Err(SyntheticLeaseIssueStatus::StateUnavailable),
    }
}

fn persist_state(path: &Path, encoded: &[u8]) -> Result<(), SyntheticLeaseIssueStatus> {
    let parent = path
        .parent()
        .ok_or(SyntheticLeaseIssueStatus::PersistenceFailed)?;
    if fs::symlink_metadata(parent).is_ok_and(|metadata| !metadata.file_type().is_dir()) {
        return Err(SyntheticLeaseIssueStatus::PersistenceFailed);
    }
    fs::create_dir_all(parent).map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)?;
    if fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        return Err(SyntheticLeaseIssueStatus::PersistenceFailed);
    }
    atomic_replace(path, encoded).map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| SyntheticLeaseIssueStatus::PersistenceFailed)
}

fn exchange(
    socket_path: &Path,
    request: &BridgeMessage,
) -> Result<BridgeMessage, SyntheticLeaseIssueStatus> {
    let frame = encode_frame(request, ExchangeRole::CandidateRequest)
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    let mut socket =
        UnixStream::connect(socket_path).map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    socket
        .set_read_timeout(Some(BUDGET))
        .and_then(|()| socket.set_write_timeout(Some(BUDGET)))
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    write_frame(&mut socket, frame.as_slice())?;
    let response = read_frame(&mut socket)?;
    decode_frame(&response, ExchangeRole::CandidateResponse)
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)
}

fn write_frame(socket: &mut UnixStream, frame: &[u8]) -> Result<(), SyntheticLeaseIssueStatus> {
    let length =
        u32::try_from(frame.len()).map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    socket
        .write_all(&length.to_be_bytes())
        .and_then(|()| socket.write_all(frame))
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)
}

fn read_frame(socket: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, SyntheticLeaseIssueStatus> {
    let mut header = [0_u8; 4];
    socket
        .read_exact(&mut header)
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(SyntheticLeaseIssueStatus::TransportFailed);
    }
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    socket
        .read_exact(frame.as_mut_slice())
        .map_err(|_| SyntheticLeaseIssueStatus::TransportFailed)?;
    Ok(frame)
}

fn validate_response(
    response: BridgeMessage,
    expected: (u64, u64, &[u8]),
) -> Result<Vec<Vec<u8>>, SyntheticLeaseIssueStatus> {
    let (request_id, requested_epoch, expected_spki) = expected;
    let BridgeMessage::SyntheticLeaseIssueResponse {
        request_id: response_id,
        lease_epoch,
        certificate_chain,
    } = response
    else {
        return Err(SyntheticLeaseIssueStatus::ResponseRejected);
    };
    if response_id.value() != request_id || lease_epoch != requested_epoch {
        return Err(SyntheticLeaseIssueStatus::ResponseRejected);
    }
    let chain = certificate_chain
        .iter()
        .map(|certificate| certificate.as_slice().to_vec())
        .collect::<Vec<_>>();
    let parsed = chain
        .iter()
        .map(|certificate| {
            let (remaining, parsed) = parse_x509_certificate(certificate)
                .map_err(|_| SyntheticLeaseIssueStatus::ResponseRejected)?;
            if remaining.is_empty() {
                Ok(parsed)
            } else {
                Err(SyntheticLeaseIssueStatus::ResponseRejected)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = parsed
        .first()
        .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)?;
    if leaf.tbs_certificate.subject_pki.raw != expected_spki {
        return Err(SyntheticLeaseIssueStatus::ResponseRejected);
    }
    for pair in parsed.windows(2) {
        let child = pair
            .first()
            .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)?;
        let issuer = pair
            .get(1)
            .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)?;
        if child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Err(SyntheticLeaseIssueStatus::ResponseRejected);
        }
    }
    let root = parsed
        .last()
        .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)?;
    if root.issuer() != root.subject() || root.verify_signature(Some(root.public_key())).is_err() {
        return Err(SyntheticLeaseIssueStatus::ResponseRejected);
    }
    Ok(chain)
}

fn leaf_not_after_millis(chain: &[Vec<u8>]) -> Result<u64, SyntheticLeaseIssueStatus> {
    let leaf = chain
        .first()
        .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)?;
    let (remaining, certificate) =
        parse_x509_certificate(leaf).map_err(|_| SyntheticLeaseIssueStatus::ResponseRejected)?;
    if !remaining.is_empty() {
        return Err(SyntheticLeaseIssueStatus::ResponseRejected);
    }
    let seconds = u64::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| SyntheticLeaseIssueStatus::ResponseRejected)?;
    seconds
        .checked_mul(1_000)
        .ok_or(SyntheticLeaseIssueStatus::ResponseRejected)
}

fn now_millis() -> Result<u64, SyntheticLeaseIssueStatus> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SyntheticLeaseIssueStatus::InvalidContext)?
        .as_millis();
    u64::try_from(millis).map_err(|_| SyntheticLeaseIssueStatus::InvalidContext)
}

fn fresh_request_id(rng: &SystemRandom) -> Result<u64, SyntheticLeaseIssueStatus> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 8];
        rng.fill(&mut bytes)
            .map_err(|_| SyntheticLeaseIssueStatus::KeyGenerationFailed)?;
        let value = u64::from_be_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
    Err(SyntheticLeaseIssueStatus::KeyGenerationFailed)
}

fn p256_spki(point: &[u8]) -> Result<Vec<u8>, SyntheticLeaseIssueStatus> {
    if point.len() != 65 || point.first() != Some(&0x04) {
        return Err(SyntheticLeaseIssueStatus::KeyGenerationFailed);
    }
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len().saturating_add(point.len()));
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.extend_from_slice(point);
    Ok(spki)
}

fn synthetic_aaid(profile_id_hash: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(b"TEESimulator-RS synthetic RKP lease v1\0");
    context.update(profile_id_hash);
    context.update(&epoch.to_be_bytes());
    let mut value = [0_u8; 32];
    value.copy_from_slice(context.finish().as_ref());
    value
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut encoded, byte| {
        let _ = write!(encoded, "{byte:02x}");
        encoded
    })
}
