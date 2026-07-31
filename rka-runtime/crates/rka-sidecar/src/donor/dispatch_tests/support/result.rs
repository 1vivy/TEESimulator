use rka_protocol::{CborWriter, HashDomain, MessageKind, hash_bytes};

use super::{AAID, EPOCH, IRPC, PHASES, RKP_PUBLIC};

pub(super) fn expected_body(ordinal: u8, identity_hash: [u8; 32], started_ms: u64) -> Vec<u8> {
    let envelope = envelope(identity_hash, started_ms);
    let spki = format!("leaf-spki-{ordinal}");
    let leaf = format!("leaf-{ordinal}");
    let root = format!("root-{ordinal}");
    let signature = format!("transcript-signature-{ordinal}");
    let mut writer = CborWriter::with_capacity(1400);
    writer.map(2);
    writer.unsigned(0);
    writer.unsigned(u64::from(MessageKind::Generate));
    writer.unsigned(1);
    writer.map(5);
    writer.unsigned(0);
    writer.bytes(&[0xa0 | ordinal; 16]);
    writer.unsigned(1);
    writer.array(2);
    writer.bytes(leaf.as_bytes());
    writer.bytes(root.as_bytes());
    writer.unsigned(2);
    writer.bytes(&super::super::super::broker_characteristics::exact_characteristics_hash());
    writer.unsigned(3);
    let mut result = writer.finish();
    result.extend_from_slice(&envelope);
    let mut writer = CborWriter::with_capacity(256);
    writer.unsigned(4);
    writer.map(6);
    for (key, value) in [
        (0, hash_bytes(HashDomain::RkpPublic, spki.as_bytes())),
        (1, PHASES[4]),
        (2, hash_bytes(HashDomain::LeafProof, b"0123456789abcdef")),
        (3, hash_bytes(HashDomain::Aaid, AAID)),
        (4, hash_bytes(HashDomain::Envelope, &envelope)),
    ] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(5);
    writer.bytes(signature.as_bytes());
    result.extend_from_slice(&writer.finish());
    result
}

fn envelope(identity_hash: [u8; 32], started_ms: u64) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(640);
    writer.map(17);
    writer.unsigned(0);
    writer.unsigned(1);
    for (key, value) in [(1, identity_hash), (2, hash_bytes(HashDomain::Aaid, AAID))] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(3);
    writer.unsigned(EPOCH);
    for (key, value) in [(4, [0x33; 32]), (5, [0x44; 32]), (6, IRPC)] {
        writer.unsigned(key);
        writer.bytes(&value);
    }
    writer.unsigned(7);
    writer.array(1);
    writer.bytes(&RKP_PUBLIC);
    for (offset, value) in PHASES.iter().enumerate() {
        writer.unsigned(8_u64.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX)));
        writer.bytes(value);
    }
    writer.unsigned(13);
    writer.unsigned(started_ms);
    writer.unsigned(14);
    writer.unsigned(120);
    writer.unsigned(15);
    writer.unsigned(1);
    writer.unsigned(16);
    writer.unsigned(0);
    writer.finish()
}
