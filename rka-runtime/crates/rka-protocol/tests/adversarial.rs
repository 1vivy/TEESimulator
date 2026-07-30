#![allow(
    missing_docs,
    reason = "integration test names and BDD blocks define the exercised behavior"
)]

use rka_protocol::{
    CborWriter, HashDomain, ProtocolError, admit_candidate_identity, hash_cbor,
    validate_deterministic_cbor, validate_upstream_rkp_bytes,
};

#[test]
fn reject_noninteger_map_key_before_schema_allocation() {
    // Given: a deterministic map whose critical key is a text string rather than an integer.
    let payload = [0xa1, 0x61, 0x78, 0x00];

    // When: the generic deterministic-CBOR boundary parses the map.
    let result = validate_deterministic_cbor(&payload);

    // Then: the key type is rejected before a schema model can be allocated.
    assert_eq!(result, Err(ProtocolError::NonIntegerKey));
}

#[test]
fn reject_forbidden_material_custom_envelope_in_upstream_rkp_bytes() {
    // Given: canonical upstream bytes containing the complete custom envelope byte sequence.
    let envelope = [0xa1, 0x00, 0x01];
    let upstream = [0x82, 0x40, 0x43, 0xa1, 0x00, 0x01];

    // When: the standard-RKP boundary checks the exact upstream bytes.
    let result = validate_upstream_rkp_bytes(&upstream, &envelope);

    // Then: module-only envelope bytes are rejected before POST.
    assert_eq!(result, Err(ProtocolError::ForbiddenMaterial));
}

#[test]
fn reject_forbidden_material_unsupported_cross_uid_grant() {
    // Given: a valid canonical identity bound to UID 10_123 and a different authenticated UID.
    let identity = identity(10_123);

    // When: admission binds the decoded identity to UID 10_124.
    let result = admit_candidate_identity(&identity, 10_124);

    // Then: the unsupported cross-UID grant is typed and no identity escapes the boundary.
    assert_eq!(result, Err(ProtocolError::CrossUidGrant));
}

fn identity(uid: u32) -> Vec<u8> {
    let without_hash = identity_map(uid, None);
    let identity_hash = hash_cbor(HashDomain::Identity, &without_hash);
    identity_map(uid, Some(identity_hash))
}

fn identity_map(uid: u32, identity_hash: Option<[u8; 32]>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(160);
    writer.map(if identity_hash.is_some() { 6 } else { 5 });
    writer.unsigned(0);
    writer.unsigned(0);
    writer.unsigned(1);
    writer.unsigned(u64::from(uid));
    writer.unsigned(2);
    writer.array(1);
    writer.array(3);
    writer.text("org.example.fixture");
    writer.unsigned(1);
    writer.array(1);
    writer.bytes(&[0x30, 0x00]);
    writer.unsigned(3);
    writer.bytes(&[0x30, 0x00]);
    if let Some(hash) = identity_hash {
        writer.unsigned(4);
        writer.bytes(&hash);
    }
    writer.unsigned(5);
    writer.bytes(&[0x99; 32]);
    writer.finish()
}
