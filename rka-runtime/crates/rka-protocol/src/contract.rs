//! Fixed limits, errors, and replay-key layouts.

use crate::{
    CONNECT_DEADLINE_MS, CborWriter, HTTP_DEADLINE_MS, MAX_CBOR_DEPTH, MAX_DER_CERTIFICATE_BYTES,
    MAX_FRAME_BYTES, MAX_LIVE_OPERATIONS_PER_KEY, MAX_LIVE_OPERATIONS_TOTAL,
    MAX_OPERATION_INPUT_BYTES, MAX_REMOTE_KEYS, MAX_RETURNED_CHAIN_BYTES, MAX_RKP_BATCH,
    MAX_SESSIONS, MAX_UPDATE_BYTES, MAX_UPDATES_PER_OPERATION, MessageKind,
    REPLAY_MIN_PROFILE_EPOCHS, REPLAY_MIN_SECONDS, RequestId, SESSION_IDLE_MS, SessionId,
    TTL_SECONDS, UDS_DEADLINE_MS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[non_exhaustive]
pub enum RkaErrorCode {
    InvalidRequest = 1,
    PolicyRejected = 2,
    UnsupportedAlgorithm = 3,
    UnsupportedPurpose = 4,
    UnsupportedDigest = 5,
    UnsupportedEcCurve = 6,
    Capacity = 7,
    StaleHandle = 8,
    Transport = 9,
    OperationLost = 10,
    Quarantined = 11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Stage {
    Frame = 1,
    Policy = 2,
    Session = 3,
    Transport = 4,
    Rkp = 5,
    KeyMint = 6,
    Lifecycle = 7,
    Storage = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyMintError {
    InvalidArgument,
    PermissionDenied,
    TooManyOperations,
    InvalidKeyBlob,
    SecureHardwareCommunicationFailed,
    OperationCancelled,
}

impl RkaErrorCode {
    #[must_use]
    pub const fn keymint_error(self) -> KeyMintError {
        match self {
            Self::InvalidRequest
            | Self::UnsupportedAlgorithm
            | Self::UnsupportedPurpose
            | Self::UnsupportedDigest
            | Self::UnsupportedEcCurve => KeyMintError::InvalidArgument,
            Self::PolicyRejected => KeyMintError::PermissionDenied,
            Self::Capacity => KeyMintError::TooManyOperations,
            Self::StaleHandle => KeyMintError::InvalidKeyBlob,
            Self::Transport | Self::Quarantined => KeyMintError::SecureHardwareCommunicationFailed,
            Self::OperationLost => KeyMintError::OperationCancelled,
        }
    }
}

impl From<RkaErrorCode> for u64 {
    fn from(value: RkaErrorCode) -> Self {
        match value {
            RkaErrorCode::InvalidRequest => 1,
            RkaErrorCode::PolicyRejected => 2,
            RkaErrorCode::UnsupportedAlgorithm => 3,
            RkaErrorCode::UnsupportedPurpose => 4,
            RkaErrorCode::UnsupportedDigest => 5,
            RkaErrorCode::UnsupportedEcCurve => 6,
            RkaErrorCode::Capacity => 7,
            RkaErrorCode::StaleHandle => 8,
            RkaErrorCode::Transport => 9,
            RkaErrorCode::OperationLost => 10,
            RkaErrorCode::Quarantined => 11,
        }
    }
}

impl From<Stage> for u64 {
    fn from(value: Stage) -> Self {
        match value {
            Stage::Frame => 1,
            Stage::Policy => 2,
            Stage::Session => 3,
            Stage::Transport => 4,
            Stage::Rkp => 5,
            Stage::KeyMint => 6,
            Stage::Lifecycle => 7,
            Stage::Storage => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AliasHandle([u8; 16]);

impl AliasHandle {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationHandle([u8; 16]);

impl OperationHandle {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSpkiHash([u8; 32]);

impl PeerSpkiHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[must_use]
pub fn frozen_limits_cbor() -> Vec<u8> {
    let values = [
        u64::try_from(MAX_FRAME_BYTES).map_or(u64::MAX, |value| value),
        u64::from(MAX_CBOR_DEPTH),
        MAX_SESSIONS,
        MAX_REMOTE_KEYS,
        MAX_LIVE_OPERATIONS_PER_KEY,
        MAX_LIVE_OPERATIONS_TOTAL,
        MAX_UPDATES_PER_OPERATION,
        u64::try_from(MAX_UPDATE_BYTES).map_or(u64::MAX, |value| value),
        u64::try_from(MAX_OPERATION_INPUT_BYTES).map_or(u64::MAX, |value| value),
        u64::try_from(MAX_RKP_BATCH).map_or(u64::MAX, |value| value),
        u64::try_from(MAX_DER_CERTIFICATE_BYTES).map_or(u64::MAX, |value| value),
        u64::try_from(MAX_RETURNED_CHAIN_BYTES).map_or(u64::MAX, |value| value),
        UDS_DEADLINE_MS,
        CONNECT_DEADLINE_MS,
        HTTP_DEADLINE_MS,
        SESSION_IDLE_MS,
        TTL_SECONDS,
        REPLAY_MIN_SECONDS,
        REPLAY_MIN_PROFILE_EPOCHS,
    ];
    let mut writer = CborWriter::with_capacity(96);
    writer.map(values.len());
    for (key, value) in values.iter().enumerate() {
        writer.unsigned(u64::try_from(key).map_or(u64::MAX, |number| number));
        writer.unsigned(*value);
    }
    writer.finish()
}

#[must_use]
pub fn session_tombstone(peer: PeerSpkiHash, profile_epoch: u64, session: SessionId) -> Vec<u8> {
    tombstone_prefix(3, (peer, profile_epoch, session)).finish()
}

#[must_use]
pub fn request_tombstone(
    session_key: (PeerSpkiHash, u64, SessionId),
    request: (RequestId, MessageKind),
) -> Vec<u8> {
    let mut writer = tombstone_prefix(5, session_key);
    writer.bytes(&request.0.bytes());
    writer.unsigned(request.1.into());
    writer.finish()
}

#[must_use]
pub fn operation_tombstone(
    session_key: (PeerSpkiHash, u64, SessionId),
    operation: OperationHandle,
) -> Vec<u8> {
    let mut writer = tombstone_prefix(4, session_key);
    writer.bytes(&operation.0);
    writer.finish()
}

fn tombstone_prefix(length: usize, session_key: (PeerSpkiHash, u64, SessionId)) -> CborWriter {
    let mut writer = CborWriter::with_capacity(96);
    writer.array(length);
    writer.bytes(&session_key.0.0);
    writer.unsigned(session_key.1);
    writer.bytes(&session_key.2.bytes());
    writer
}
