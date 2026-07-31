use std::{collections::BTreeMap, fmt, sync::Mutex, time::Duration};

use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey},
};
use rka_protocol::{AUDIT_DOMAIN, MessageKind, RequestId, RkaErrorCode, SessionId, Stage, sha256};
use rka_state::{StateError, StateStore};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use zeroize::Zeroizing;

use super::{
    AdmissionBinding, AuditChain, AuditEntry, ClientPeer, Endpoint, ProfileInput, ReceiptContext,
    RequestContext, ResponseContext, Role, SessionScope, TlsAdmission, TlsCredentials,
    TransportKind,
};

const RECEIPT_DOMAIN: &[u8] = b"TEESIM-RKA-V2/AUDIT-RECEIPT\0";

#[derive(Debug)]
struct MemoryStore(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);

impl MemoryStore {
    fn new() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }
}

impl StateStore for MemoryStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .0
            .lock()
            .map_err(|_| StateError::Storage)?
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        let maximum = output.len();
        let target = output
            .get_mut(..value.len())
            .ok_or(StateError::RecordTooLarge {
                actual: value.len(),
                maximum,
            })?;
        target.copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.0
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

#[derive(Debug)]
struct HarnessError(&'static str);

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for HarnessError {}

struct ParsedReceipt<'a> {
    body: &'a [u8],
    signature: &'a [u8],
    epoch: u64,
    transport: u64,
    correlation: &'a [u8],
    head: &'a [u8],
    sequence: u64,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn byte(&mut self) -> Result<u8, HarnessError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(HarnessError("truncated CBOR"))?;
        self.position = self.position.saturating_add(1);
        Ok(value)
    }

    fn marker(&mut self, expected: u8) -> Result<(), HarnessError> {
        if self.byte()? == expected {
            Ok(())
        } else {
            Err(HarnessError("unexpected CBOR marker"))
        }
    }

    fn unsigned(&mut self) -> Result<u64, HarnessError> {
        match self.byte()? {
            value @ 0..=23 => Ok(u64::from(value)),
            0x18 => {
                let value = self.byte()?;
                if value < 24 {
                    Err(HarnessError("noncanonical integer"))
                } else {
                    Ok(u64::from(value))
                }
            }
            0x19 => {
                let bytes = self.take(2)?;
                let value =
                    u16::from_be_bytes(bytes.try_into().map_err(|_| HarnessError("integer"))?);
                if u8::try_from(value).is_ok() {
                    Err(HarnessError("noncanonical integer"))
                } else {
                    Ok(u64::from(value))
                }
            }
            _ => Err(HarnessError("unsupported integer")),
        }
    }

    fn byte_string(&mut self) -> Result<&'a [u8], HarnessError> {
        let marker = self.byte()?;
        let length = match marker {
            value @ 0x40..=0x57 => usize::from(
                value
                    .checked_sub(0x40)
                    .ok_or(HarnessError("byte string length"))?,
            ),
            0x58 => {
                let value = self.byte()?;
                if value < 24 {
                    return Err(HarnessError("noncanonical byte string"));
                }
                usize::from(value)
            }
            _ => return Err(HarnessError("unsupported byte string")),
        };
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HarnessError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HarnessError("length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(HarnessError("truncated CBOR"))?;
        self.position = end;
        Ok(value)
    }

    fn complete(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn parse_receipt(bytes: &[u8]) -> Result<ParsedReceipt<'_>, HarnessError> {
    let mut outer = Cursor::new(bytes);
    outer.marker(0x82)?;
    let body = outer.byte_string()?;
    let signature = outer.byte_string()?;
    if signature.len() != 64 || !outer.complete() {
        return Err(HarnessError("invalid receipt envelope"));
    }
    let mut inner = Cursor::new(body);
    inner.marker(0xa5)?;
    inner.marker(0)?;
    let epoch = inner.unsigned()?;
    inner.marker(1)?;
    let transport = inner.unsigned()?;
    inner.marker(2)?;
    let correlation = inner.byte_string()?;
    inner.marker(3)?;
    let head = inner.byte_string()?;
    inner.marker(4)?;
    let sequence = inner.unsigned()?;
    if correlation.len() != 32 || head.len() != 32 || !inner.complete() {
        return Err(HarnessError("invalid receipt body"));
    }
    Ok(ParsedReceipt {
        body,
        signature,
        epoch,
        transport,
        correlation,
        head,
        sequence,
    })
}

fn unsigned(output: &mut Vec<u8>, value: u64) -> Result<(), HarnessError> {
    match value {
        0..=23 => output.push(u8::try_from(value).map_err(|_| HarnessError("integer"))?),
        24..=255 => {
            output.push(0x18);
            output.push(u8::try_from(value).map_err(|_| HarnessError("integer"))?);
        }
        _ => return Err(HarnessError("test integer too large")),
    }
    Ok(())
}

fn bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), HarnessError> {
    if value.len() < 24 {
        output.push(
            0x40_u8
                .checked_add(u8::try_from(value.len()).map_err(|_| HarnessError("bytes"))?)
                .ok_or(HarnessError("bytes"))?,
        );
    } else {
        output.push(0x58);
        output.push(u8::try_from(value.len()).map_err(|_| HarnessError("bytes"))?);
    }
    output.extend_from_slice(value);
    Ok(())
}

fn independent_entry(
    entry: AuditEntry,
    raw_correlation: [u8; 32],
) -> Result<Vec<u8>, HarnessError> {
    let mut detail = vec![0xa2, 0];
    unsigned(&mut detail, entry.stage.into())?;
    detail.push(1);
    unsigned(&mut detail, entry.request_kind.into())?;
    let mut detail_preimage = vec![0xa2, 0];
    unsigned(&mut detail_preimage, entry.error.into())?;
    detail_preimage.push(1);
    detail_preimage.extend_from_slice(&detail);
    let mut detail_domain = AUDIT_DOMAIN.to_vec();
    detail_domain.extend_from_slice(&detail_preimage);
    let detail_hash = sha256(&detail_domain);
    let mut encoded = vec![0xa4, 0];
    unsigned(&mut encoded, entry.stage.into())?;
    encoded.push(1);
    unsigned(&mut encoded, entry.request_kind.into())?;
    encoded.push(2);
    bytes(&mut encoded, &detail_hash)?;
    encoded.push(3);
    bytes(&mut encoded, &sha256(&raw_correlation))?;
    Ok(encoded)
}

#[test]
fn audit_receipt_is_independently_decoded_and_recomputed() -> Result<(), Box<dyn std::error::Error>>
{
    let store = MemoryStore::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
    let private = Zeroizing::new(pkcs8.as_ref().to_vec());
    let mut chain = AuditChain::load(&store, &private)?;
    let entry_raw = [0xa1; 32];
    let entry = AuditEntry::new(
        (Stage::Transport, MessageKind::Finish),
        RkaErrorCode::InvalidRequest,
        entry_raw,
    );
    let encoded_entry = independent_entry(entry, entry_raw)?;
    let mut chain_preimage = AUDIT_DOMAIN.to_vec();
    chain_preimage.extend_from_slice(&[0; 32]);
    chain_preimage.extend_from_slice(&encoded_entry);
    let expected_head = sha256(&chain_preimage);
    assert_eq!(chain.append(entry)?, expected_head);

    let receipt_raw = [0xa2; 32];
    let context = ReceiptContext::new(8, TransportKind::DirectPinnedTls, receipt_raw);
    let receipt = chain.receipt(context);
    let encoded = receipt.encode();
    let parsed = parse_receipt(&encoded)?;
    assert_eq!(parsed.epoch, 8);
    assert_eq!(parsed.transport, 1);
    assert_eq!(parsed.correlation, sha256(&receipt_raw));
    assert_eq!(parsed.head, expected_head);
    assert_eq!(parsed.sequence, 1);
    let mut signed = RECEIPT_DOMAIN.to_vec();
    signed.extend_from_slice(parsed.body);
    UnparsedPublicKey::new(&ED25519, chain.public_key())
        .verify(&signed, parsed.signature)
        .map_err(|_| HarnessError("independent signature rejection"))?;
    assert!(
        UnparsedPublicKey::new(&ED25519, [0x55; 32])
            .verify(&signed, parsed.signature)
            .is_err()
    );
    let mut tampered = encoded.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    let tampered_receipt = parse_receipt(&tampered)?;
    assert!(
        UnparsedPublicKey::new(&ED25519, chain.public_key())
            .verify(&signed, tampered_receipt.signature)
            .is_err()
    );
    let truncated = encoded
        .get(..encoded.len().saturating_sub(1))
        .ok_or(HarnessError("truncation"))?;
    assert!(parse_receipt(truncated).is_err());
    let mut extended = encoded.clone();
    extended.push(0);
    assert!(parse_receipt(&extended).is_err());
    let digest = sha256(&encoded);
    let mut seen = Vec::new();
    assert!(!seen.contains(&digest));
    seen.push(digest);
    assert!(seen.contains(&sha256(&encoded)));

    let mut captured = encoded.clone();
    for value in store.0.lock().map_err(|_| StateError::Storage)?.values() {
        captured.extend_from_slice(value);
    }
    captured.extend_from_slice(format!("{chain:?}{receipt:?}{context:?}").as_bytes());
    capture_canaries(captured, (&private, entry_raw, receipt_raw))
}

fn capture_canaries(
    mut captured: Vec<u8>,
    audit: (&Zeroizing<Vec<u8>>, [u8; 32], [u8; 32]),
) -> Result<(), Box<dyn std::error::Error>> {
    let (private, entry_raw, receipt_raw) = audit;
    let alias = "alias-canary.invalid";
    let local_pin = [0xa3; 32];
    let peer_pin = [0xa4; 32];
    let identity = [0xa5; 32];
    let root_hash = [0xa6; 32];
    let transport_pin = [0xa7; 32];
    let profile_id = [0xa8; 32];
    let session_id = [0xa9; 32];
    let bearer_token = [0xaa; 32];
    let transcript = [0xab; 32];
    let request_id = [0xac; 16];
    let scope_peer = [0xad; 32];
    let endpoint = Endpoint::parse(alias, 443)?;
    let profile = ProfileInput {
        epoch: 1,
        local_role: Role::Candidate,
        transport: TransportKind::DirectPinnedTls,
        endpoint,
        local_spki: local_pin,
        peer_spki: peer_pin,
        peer_trust: vec![CertificateDer::from(b"certificate-canary".to_vec())],
        allowed_identities: vec![identity],
        root_hash,
        policy_version: 1,
    };
    let credentials = TlsCredentials::new(
        vec![CertificateDer::from(b"certificate-canary".to_vec())],
        PrivatePkcs8KeyDer::from(private.to_vec()).into(),
    );
    let peer = ClientPeer::new(
        vec![CertificateDer::from(b"certificate-canary".to_vec())],
        ServerName::try_from(alias.to_owned())?,
        transport_pin,
    );
    let admission = AdmissionBinding {
        profile_id,
        session_id,
        candidate_nonce: bearer_token,
        transcript_hash: transcript,
    };
    let request = RequestContext::new(SessionId::new(session_id), MessageKind::Finish, 1);
    let response = ResponseContext::success(RequestId::new(request_id), MessageKind::Result, 0);
    let scope = SessionScope::new(rka_protocol::PeerSpkiHash::new(scope_peer), 1);
    let path_error = Endpoint::parse("/data/adb/modules/canary/private/key", 443)
        .err()
        .ok_or(HarnessError("path unexpectedly accepted"))?;
    captured.extend_from_slice(
        format!(
            "{profile:?}{credentials:?}{peer:?}{admission:?}{:?}{request:?}{response:?}\
             {scope:?}{path_error}",
            TlsAdmission::new(admission, Duration::from_secs(1))
        )
        .as_bytes(),
    );
    for forbidden in [
        entry_raw.as_slice(),
        receipt_raw.as_slice(),
        private.as_slice(),
        local_pin.as_slice(),
        peer_pin.as_slice(),
        identity.as_slice(),
        root_hash.as_slice(),
        transport_pin.as_slice(),
        profile_id.as_slice(),
        session_id.as_slice(),
        bearer_token.as_slice(),
        transcript.as_slice(),
        request_id.as_slice(),
        scope_peer.as_slice(),
        b"certificate-canary".as_slice(),
        alias.as_bytes(),
        b"/data/adb/modules/canary/private/key".as_slice(),
    ] {
        assert!(
            !captured
                .windows(forbidden.len())
                .any(|value| value == forbidden)
        );
    }
    Ok(())
}
