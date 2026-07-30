//! Typed, bounded RKA v2 wire contract.
#![allow(
    missing_docs,
    reason = "wire fields are exhaustively documented in docs/RKA_PROTOCOL_V2.md"
)]

#[doc(hidden)]
pub mod cbor;
#[doc(hidden)]
pub mod cbor_validate;
mod constants;
mod contract;
#[doc(hidden)]
pub mod envelope;
mod error;
mod frame;
mod hash;
#[doc(hidden)]
pub mod identity;
mod record;
#[doc(hidden)]
pub mod request;
#[doc(hidden)]
pub mod response;
mod state;
mod upstream;

pub use cbor::CborWriter;
pub use cbor_validate::validate_deterministic_cbor;
pub use constants::*;
pub use contract::{
    AliasHandle, KeyMintError, OperationHandle, PeerSpkiHash, RkaErrorCode, Stage,
    frozen_limits_cbor, operation_tombstone, request_tombstone, session_tombstone,
};
pub use envelope::{Envelope, decode_envelope};
pub use error::ProtocolError;
pub use frame::{
    Frame, FrameBody, FrameContext, Hello, decode_frame, encode_frame,
    encode_frame_without_transcript,
};
pub use hash::{HashDomain, hash_bytes, hash_cbor, sha256, transcript_hash};
pub use identity::{
    CandidateIdentity, PackageIdentity, admit_candidate_identity, decode_candidate_identity,
};
pub use record::{Payload, Record, decode_record, encode_record};
pub use request::{ForegroundRequest, decode_foreground_request};
pub use response::validate_response_body;
pub use state::{
    AliasState, CapabilityBitmap, MessageKind, ProtocolState, RequestId, SessionId, Transition,
};
pub use upstream::validate_upstream_rkp_bytes;
