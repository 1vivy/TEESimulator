#![allow(
    missing_docs,
    reason = "integration test names and BDD blocks define the exercised behavior"
)]

use rka_protocol::{
    Frame, FrameBody, FrameContext, MessageKind, ProtocolError, RequestId, SessionId, decode_frame,
    encode_frame, validate_deterministic_cbor,
};

include!("support/schema_vectors.rs");
include!("support/schema_results.rs");

#[test]
fn begin_encoder_emits_every_required_field_and_roundtrips() {
    // Given: the frozen BEGIN body with a deterministic alias handle.
    let frame = Frame::new(
        FrameContext::new(
            (RequestId::new([0x22; 16]), SessionId::new([0x11; 32])),
            (7, 1),
        ),
        MessageKind::Begin,
        FrameBody::Begin([0x55; 16]),
    );

    // When: the production encoder output crosses the production decoder boundary.
    let encoded = encode_frame(&frame);
    let decoded = decode_frame(&encoded);

    // Then: BEGIN's required purpose, digest, and padding fields were not omitted.
    assert_eq!(decoded, Ok(frame));
}

#[test]
fn every_frozen_body_schema_roundtrips_exactly() {
    // Given: every frozen request, response, result, error, and leaf-proof body kind.
    let vectors = schema_vectors();
    let golden = schema_manifest();

    // When: each independent canonical frame crosses the production decoder and encoder.
    // Then: all 21 schemas are canonical, accepted, and byte-exact after round-trip.
    assert_eq!(vectors.len(), 21);
    assert_eq!(golden.len(), vectors.len());
    for (vector, (golden_name, golden_bytes)) in vectors.iter().zip(golden) {
        assert_eq!(vector.name, golden_name);
        assert_eq!(vector.bytes, golden_bytes, "{}", vector.name);
        assert_eq!(
            validate_deterministic_cbor(&vector.bytes),
            Ok(()),
            "{} must be canonical",
            vector.name
        );
        assert_eq!(
            decode_frame(&vector.bytes).map(|frame| encode_frame(&frame)),
            Ok(vector.bytes.clone()),
            "{}",
            vector.name
        );
    }
}

#[test]
fn required_fields_and_fixed_tags_reject_schema_mutations() {
    // Given: the exact old one-field BEGIN emission and a wrong BEGIN-result max-chunk tag.
    let old_begin = old_begin_frame();
    let wrong_result_tag = wrong_begin_result_frame();

    // When: both mutations cross the production schema decoder.
    let observed = [decode_frame(&old_begin), decode_frame(&wrong_result_tag)];

    // Then: omission and fixed-tag asymmetries are rejected with their typed errors.
    assert!(matches!(observed[0], Err(ProtocolError::MissingField)));
    assert!(matches!(observed[1], Err(ProtocolError::UnsupportedValue)));
}

fn schema_manifest() -> Vec<(&'static str, Vec<u8>)> {
    include_str!("../../../../two-phone/src/test/resources/rka-v2/schema-matrix.txt")
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(name, encoded)| (name, decode_hex(encoded)))
        .collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}
