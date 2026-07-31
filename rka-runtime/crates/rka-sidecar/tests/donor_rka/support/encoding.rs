use rka_protocol::{CborWriter, HashDomain, hash_cbor};

pub const AAID: &[u8] = b"authoritative-aaid";
pub const PROFILE_EPOCH: u64 = 9;
pub const CANDIDATE_NONCE: [u8; 32] = [0x33; 32];
pub const DONOR_NONCE: [u8; 32] = [0x44; 32];
pub const PEER: [u8; 32] = [0x55; 32];
pub const PROFILE: [u8; 32] = [0x66; 32];
pub const SESSION: [u8; 32] = [0x77; 32];
pub const IRPC: [u8; 32] = [0x88; 32];
pub const RKP_PUBLIC: [u8; 32] = [0x91; 32];
pub const CSR: [u8; 32] = [0x92; 32];
pub const SERVER_BODY: [u8; 32] = [0x93; 32];
pub const CHALLENGE: [u8; 32] = [0x94; 32];
pub const RESPONSE: [u8; 32] = [0x95; 32];
pub const CHAIN: [u8; 32] = [0x96; 32];
pub const ALIAS: [u8; 16] = [0xa1; 16];
pub const RKP_CHAIN: [&[u8]; 2] = [b"rkp-leaf", b"rkp-root"];

const LINEAGE_HASH: [u8; 32] = [0x22; 32];

pub const fn request_id(value: u8) -> [u8; 16] {
    [value; 16]
}

pub fn identity() -> (Vec<u8>, [u8; 32]) {
    let mut unsigned = CborWriter::with_capacity(256);
    encode_identity_prefix(&mut unsigned, 5);
    unsigned.unsigned(5);
    unsigned.bytes(&LINEAGE_HASH);
    let identity_hash = hash_cbor(HashDomain::Identity, &unsigned.finish());
    let mut writer = CborWriter::with_capacity(256);
    encode_identity_prefix(&mut writer, 6);
    writer.unsigned(4);
    writer.bytes(&identity_hash);
    writer.unsigned(5);
    writer.bytes(&LINEAGE_HASH);
    (writer.finish(), identity_hash)
}

fn encode_identity_prefix(writer: &mut CborWriter, map_size: usize) {
    writer.map(map_size);
    writer.unsigned(0);
    writer.unsigned(0);
    writer.unsigned(1);
    writer.unsigned(10_001);
    writer.unsigned(2);
    writer.array(1);
    writer.array(3);
    writer.text("com.example.candidate");
    writer.unsigned(1);
    writer.array(1);
    writer.bytes(b"signer");
    writer.unsigned(3);
    writer.bytes(AAID);
}

pub fn envelope(
    identity_hash: [u8; 32],
    aaid_hash: [u8; 32],
    nonce: [u8; 32],
    csr: [u8; 32],
    irpc: [u8; 32],
) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(512);
    writer.map(17);
    for (key, value) in [(0, None), (1, Some(identity_hash)), (2, Some(aaid_hash))] {
        writer.unsigned(key);
        if let Some(bytes) = value {
            writer.bytes(&bytes);
        } else {
            writer.unsigned(1);
        }
    }
    writer.unsigned(3);
    writer.unsigned(PROFILE_EPOCH);
    for (key, value) in [(4, nonce), (5, DONOR_NONCE), (6, irpc)] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(7);
    writer.array(1);
    writer.bytes(&RKP_PUBLIC);
    for (key, value) in [
        (8, csr),
        (9, SERVER_BODY),
        (10, CHALLENGE),
        (11, RESPONSE),
        (12, CHAIN),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(13);
    writer.unsigned(0);
    writer.unsigned(14);
    writer.unsigned(120);
    writer.unsigned(15);
    writer.unsigned(1);
    writer.unsigned(16);
    writer.unsigned(0);
    writer.finish()
}
