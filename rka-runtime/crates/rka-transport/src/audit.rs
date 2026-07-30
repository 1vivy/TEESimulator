use core::fmt;

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rka_protocol::{AUDIT_DOMAIN, CborWriter, MessageKind, RkaErrorCode, Stage, sha256};
use rka_state::{StateError, StateStore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    TransportKind,
    audit_codec::{decode_state, encode_state, entry_cbor, receipt_body},
};

const AUDIT_KEY: &[u8] = b"rka-audit-v2";
const RECEIPT_DOMAIN: &[u8] = b"TEESIM-RKA-V2/AUDIT-RECEIPT\0";
const MAX_RECEIPTS: usize = 128;

/// Redacted audit event containing only frozen tags and hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AuditEntry {
    /// Frozen stage tag.
    pub(crate) stage: Stage,
    /// Frozen request kind.
    pub(crate) request_kind: MessageKind,
    /// Frozen RKA failure code.
    pub(crate) error: RkaErrorCode,
    /// Hashed, redacted correlation.
    pub(crate) correlation_hash: [u8; 32],
}

impl AuditEntry {
    /// Creates one redacted event from frozen tags and a hashed correlation.
    #[must_use]
    pub fn new(
        tags: (Stage, MessageKind),
        error: RkaErrorCode,
        correlation_hash: [u8; 32],
    ) -> Self {
        Self {
            stage: tags.0,
            request_kind: tags.1,
            error,
            correlation_hash: sha256(&correlation_hash),
        }
    }
}

/// Authority-free input for a receipt signed from persisted audit state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReceiptContext {
    epoch: u64,
    transport: TransportKind,
    correlation: [u8; 32],
}

impl ReceiptContext {
    /// Creates receipt coordinates without accepting an audit head or sequence.
    #[must_use]
    pub fn new(epoch: u64, transport: TransportKind, correlation: [u8; 32]) -> Self {
        Self {
            epoch,
            transport,
            correlation: sha256(&correlation),
        }
    }

    pub(crate) const fn parts(self) -> (u64, TransportKind, [u8; 32]) {
        (self.epoch, self.transport, self.correlation)
    }
}

/// Persisted chained audit state and transport-key signer.
pub struct AuditChain<'a, S: StateStore> {
    store: &'a S,
    signer: Ed25519KeyPair,
    head: [u8; 32],
    sequence: u64,
}

impl<S: StateStore> fmt::Debug for AuditChain<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditChain")
            .field("signer", &"[redacted]")
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl<'a, S: StateStore> AuditChain<'a, S> {
    /// Loads chain continuity and parses the transport Ed25519 private state.
    pub fn load(store: &'a S, private: &Zeroizing<Vec<u8>>) -> Result<Self, AuditError> {
        let signer = Ed25519KeyPair::from_pkcs8(private).map_err(|_| AuditError::Key)?;
        let mut bytes = [0_u8; 128];
        let (sequence, head) = match store.read(AUDIT_KEY, &mut bytes) {
            Ok(length) => decode_state(bytes.get(..length).ok_or(AuditError::Corrupt)?)?,
            Err(StateError::Missing) => (0, [0_u8; 32]),
            Err(error) => return Err(AuditError::State(error)),
        };
        Ok(Self {
            store,
            signer,
            head,
            sequence,
        })
    }

    /// Atomically appends one canonical chained entry.
    pub fn append(&mut self, entry: AuditEntry) -> Result<[u8; 32], AuditError> {
        let body = entry_cbor(entry);
        let mut preimage = Vec::with_capacity(
            AUDIT_DOMAIN
                .len()
                .saturating_add(32)
                .saturating_add(body.len()),
        );
        preimage.extend_from_slice(AUDIT_DOMAIN);
        preimage.extend_from_slice(&self.head);
        preimage.extend_from_slice(&body);
        let next = sha256(&preimage);
        let sequence = self.sequence.checked_add(1).ok_or(AuditError::Capacity)?;
        self.store
            .replace(AUDIT_KEY, &encode_state(sequence, next))
            .map_err(AuditError::State)?;
        self.sequence = sequence;
        self.head = next;
        Ok(next)
    }

    /// Signs a receipt whose authority comes only from persisted chain state.
    pub fn receipt(&self, context: ReceiptContext) -> AuditReceipt {
        let body = receipt_body(context, (self.head, self.sequence));
        let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len().saturating_add(body.len()));
        message.extend_from_slice(RECEIPT_DOMAIN);
        message.extend_from_slice(&body);
        AuditReceipt {
            body,
            signature: self.signer.sign(&message).as_ref().to_vec(),
        }
    }

    /// Returns the externally pinnable Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        <[u8; 32]>::try_from(self.signer.public_key().as_ref()).map_or([0; 32], |key| key)
    }
}

/// Signed canonical audit receipt with redacted debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditReceipt {
    body: Vec<u8>,
    signature: Vec<u8>,
}

impl AuditReceipt {
    /// Returns canonical signed bytes for external transport.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(self.body.len().saturating_add(72));
        writer.array(2);
        writer.bytes(&self.body);
        writer.bytes(&self.signature);
        writer.finish()
    }

    #[cfg(test)]
    pub(crate) fn flip_signature_bit(&mut self) {
        if let Some(byte) = self.signature.first_mut() {
            *byte ^= 1;
        }
    }
}

impl fmt::Debug for AuditReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditReceipt([redacted signed receipt])")
    }
}

/// Stateful receipt verifier that rejects replay.
#[derive(Debug)]
pub struct ReceiptVerifier {
    public_key: [u8; 32],
    seen: Vec<[u8; 32]>,
}

impl ReceiptVerifier {
    /// Creates a verifier bound to one externally pinned transport key.
    #[must_use]
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            seen: Vec::new(),
        }
    }

    /// Verifies exact bytes, signature, and one-time receipt use.
    pub fn verify(&mut self, receipt: &AuditReceipt) -> Result<(), AuditError> {
        if receipt.signature.len() != 64 || self.seen.len() >= MAX_RECEIPTS {
            return Err(AuditError::Receipt);
        }
        let mut message =
            Vec::with_capacity(RECEIPT_DOMAIN.len().saturating_add(receipt.body.len()));
        message.extend_from_slice(RECEIPT_DOMAIN);
        message.extend_from_slice(&receipt.body);
        UnparsedPublicKey::new(&ED25519, self.public_key)
            .verify(&message, &receipt.signature)
            .map_err(|_| AuditError::Receipt)?;
        let digest = sha256(&receipt.encode());
        if self.seen.contains(&digest) {
            return Err(AuditError::Replay);
        }
        self.seen.push(digest);
        Ok(())
    }

    /// Parses and verifies exact canonical receipt bytes.
    pub fn verify_encoded(&mut self, bytes: &[u8]) -> Result<(), AuditError> {
        let (body, signature) = crate::audit_codec::decode_receipt(bytes)?;
        self.verify(&AuditReceipt { body, signature })
    }
}

/// Redacted audit persistence or verification error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuditError {
    /// Transport signing key is invalid.
    #[error("audit signing key is invalid")]
    Key,
    /// Persisted audit state is malformed.
    #[error("audit state is corrupt")]
    Corrupt,
    /// Audit sequence or verifier capacity is exhausted.
    #[error("audit capacity is exhausted")]
    Capacity,
    /// Signature or receipt encoding is invalid.
    #[error("audit receipt is invalid")]
    Receipt,
    /// Receipt bytes were already accepted.
    #[error("audit receipt replay rejected")]
    Replay,
    /// Protected storage failed.
    #[error("audit storage failed")]
    State(#[source] StateError),
}
