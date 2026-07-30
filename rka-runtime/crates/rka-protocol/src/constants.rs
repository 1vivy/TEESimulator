//! Frozen numeric tags, limits, and domain separators.

pub const PROTOCOL_VERSION: u64 = 2;
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const MAX_CBOR_DEPTH: u8 = 8;
pub const MAX_SESSIONS: u64 = 4;
pub const MAX_REMOTE_KEYS: u64 = 4;
pub const MAX_LIVE_OPERATIONS_PER_KEY: u64 = 1;
pub const MAX_LIVE_OPERATIONS_TOTAL: u64 = 4;
pub const MAX_UPDATES_PER_OPERATION: u64 = 128;
pub const MAX_UPDATE_BYTES: usize = 65_536;
pub const MAX_OPERATION_INPUT_BYTES: usize = 1_048_576;
pub const MAX_RKP_BATCH: usize = 20;
pub const MAX_DER_CERTIFICATE_BYTES: usize = 65_536;
pub const MAX_RETURNED_CHAIN_BYTES: usize = 524_288;
pub const UDS_DEADLINE_MS: u64 = 5_000;
pub const CONNECT_DEADLINE_MS: u64 = 10_000;
pub const HTTP_DEADLINE_MS: u64 = 20_000;
pub const SESSION_IDLE_MS: u64 = 30_000;
pub const TTL_SECONDS: u64 = 120;
pub const MAX_USES: u64 = 1;
pub const REPLAY_MIN_SECONDS: u64 = 86_400;
pub const REPLAY_MIN_PROFILE_EPOCHS: u64 = 2;
pub const REQUIRED_CAPABILITIES: u64 = 0x0f;

pub const FRAME_DOMAIN: &[u8] = b"TEESIM-RKA-V2/FRAME\0";
pub const IDENTITY_DOMAIN: &[u8] = b"TEESIM-RKA-V2/IDENTITY\0";
pub const AAID_DOMAIN: &[u8] = b"TEESIM-RKA-V2/AAID\0";
pub const PROFILE_DOMAIN: &[u8] = b"TEESIM-RKA-V2/PROFILE\0";
pub const IRPC_DOMAIN: &[u8] = b"TEESIM-RKA-V2/IRPC\0";
pub const RKP_PUBLIC_DOMAIN: &[u8] = b"TEESIM-RKA-V2/RKP-PUBLIC\0";
pub const CHAIN_SET_DOMAIN: &[u8] = b"TEESIM-RKA-V2/CHAIN-SET\0";
pub const ENVELOPE_DOMAIN: &[u8] = b"TEESIM-RKA-V2/ENVELOPE\0";
pub const LEAF_PROOF_DOMAIN: &[u8] = b"TEESIM-RKA-V2/LEAF-PROOF\0";
pub const AUDIT_DOMAIN: &[u8] = b"TEESIM-RKA-V2/AUDIT\0";

pub const MAX_PACKAGES: usize = 16;
pub const MAX_PACKAGE_NAME_BYTES: usize = 255;
pub const MAX_CURRENT_SIGNERS: usize = 8;
pub const MAX_SIGNER_BYTES: usize = 8_192;
pub const MAX_AAID_BYTES: usize = 131_072;
pub const MAX_ATTESTATION_CHALLENGE_BYTES: usize = 64;
pub const MIN_ATTESTATION_CHALLENGE_BYTES: usize = 16;
