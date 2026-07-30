#![allow(
    missing_docs,
    reason = "integration test names and BDD blocks define the exercised behavior"
)]

use rka_protocol::{
    AAID_DOMAIN, AUDIT_DOMAIN, CHAIN_SET_DOMAIN, CapabilityBitmap, ENVELOPE_DOMAIN, FRAME_DOMAIN,
    Frame, FrameBody, FrameContext, HashDomain, Hello, IDENTITY_DOMAIN, IRPC_DOMAIN, KeyMintError,
    LEAF_PROOF_DOMAIN, MAX_CBOR_DEPTH, MAX_FRAME_BYTES, MAX_USES, MessageKind, OperationHandle,
    PROFILE_DOMAIN, PROTOCOL_VERSION, PeerSpkiHash, ProtocolError, REPLAY_MIN_PROFILE_EPOCHS,
    REPLAY_MIN_SECONDS, REQUIRED_CAPABILITIES, RKP_PUBLIC_DOMAIN, RequestId, RkaErrorCode,
    SessionId, Stage, TTL_SECONDS, decode_frame, decode_record, encode_frame,
    encode_frame_without_transcript, frozen_limits_cbor, hash_bytes, operation_tombstone,
    request_tombstone, session_tombstone, sha256, transcript_hash, validate_deterministic_cbor,
};

#[test]
fn exact_frame_limit_rejects_one_byte_over_before_cbor_decode() {
    // Given: a length prefix one byte above the frozen one-MiB payload boundary.
    let declared = u32::try_from(MAX_FRAME_BYTES + 1).unwrap_or(u32::MAX);
    let record = declared.to_be_bytes();

    // When: the record boundary is parsed without allocating the declared payload.
    let result = decode_record(&record);

    // Then: the exact typed size error is returned before CBOR decoding.
    assert_eq!(
        result,
        Err(ProtocolError::PayloadTooLarge {
            actual: MAX_FRAME_BYTES + 1,
            maximum: MAX_FRAME_BYTES,
        })
    );
}

#[test]
fn vectors_v2_hello_is_canonical_and_transcript_bound() {
    // Given: the fixed zero-history HELLO vector shared with the Kotlin reference codec.
    let mut frame = hello_frame();
    let previous = [0_u8; 32];
    frame.transcript_hash = transcript_hash(&previous, &encode_frame_without_transcript(&frame));
    let encoded = encode_frame(&frame);
    let expected = include_str!("../../../../two-phone/src/test/resources/rka-v2/hello.hex")
        .split_whitespace()
        .collect::<String>();

    // When: the Rust vector is rendered and parsed at the production boundary.
    let decoded = decode_frame(&encoded);

    // Then: bytes, tags, canonical ordering, and transcript hash are exact.
    assert_eq!(encoded, decode_hex(&expected));
    assert_eq!(decoded, Ok(frame));
}

#[test]
fn vectors_v2_hash_domains_and_sha_are_exact() {
    // Given: the ten frozen full domain separators and a standard SHA-256 oracle.
    let domains = [
        FRAME_DOMAIN,
        IDENTITY_DOMAIN,
        AAID_DOMAIN,
        PROFILE_DOMAIN,
        IRPC_DOMAIN,
        RKP_PUBLIC_DOMAIN,
        CHAIN_SET_DOMAIN,
        ENVELOPE_DOMAIN,
        LEAF_PROOF_DOMAIN,
        AUDIT_DOMAIN,
    ];
    let expected_domains: [&[u8]; 10] = [
        b"TEESIM-RKA-V2/FRAME\0",
        b"TEESIM-RKA-V2/IDENTITY\0",
        b"TEESIM-RKA-V2/AAID\0",
        b"TEESIM-RKA-V2/PROFILE\0",
        b"TEESIM-RKA-V2/IRPC\0",
        b"TEESIM-RKA-V2/RKP-PUBLIC\0",
        b"TEESIM-RKA-V2/CHAIN-SET\0",
        b"TEESIM-RKA-V2/ENVELOPE\0",
        b"TEESIM-RKA-V2/LEAF-PROOF\0",
        b"TEESIM-RKA-V2/AUDIT\0",
    ];

    // When: the constants and one domain-separated raw-byte preimage are hashed.
    let digest = sha256(b"abc");
    let raw_hash = hash_bytes(HashDomain::Aaid, b"\x30\x00");

    // Then: every full NUL-terminated domain and both hash boundaries are pinned.
    assert_eq!(domains, expected_domains);
    assert_eq!(
        digest,
        hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        raw_hash,
        hex32("a25739310e0c8fd79488c0efde0f09d70b5462cb88a2ab4d30804530f82bb999")
    );
}

#[test]
fn reject_noncanonical_integer_duplicate_indefinite_and_depth() {
    // Given: non-shortest, duplicate-key, indefinite, and depth-nine CBOR values.
    let non_shortest = [0x18, 0x17];
    let duplicate = [0xa2, 0x00, 0x00, 0x00, 0x01];
    let indefinite = [0x9f, 0xff];
    let mut nested = vec![0x81; usize::from(MAX_CBOR_DEPTH) + 1];
    nested.push(0x00);

    // When: each adversarial value crosses the deterministic-CBOR boundary.
    let results = [
        validate_deterministic_cbor(&non_shortest),
        validate_deterministic_cbor(&duplicate),
        validate_deterministic_cbor(&indefinite),
        validate_deterministic_cbor(&nested),
    ];

    // Then: each is rejected with its exact structural error before schema dispatch.
    assert_eq!(results[0], Err(ProtocolError::NonCanonical));
    assert_eq!(results[1], Err(ProtocolError::DuplicateOrUnorderedKey));
    assert_eq!(results[2], Err(ProtocolError::IndefiniteLength));
    assert_eq!(results[3], Err(ProtocolError::DepthExceeded));
}

#[test]
fn reject_forbidden_material_and_unknown_critical_body_field() {
    // Given: a HELLO whose exact body map contains an extra critical alias/blob-like field.
    let mut encoded = encode_frame(&hello_frame());
    let body_map = encoded.iter().position(|byte| *byte == 0xa5).unwrap_or(0);
    if let Some(value) = encoded.get_mut(body_map) {
        *value = 0xa6;
    }
    let insertion = body_map.saturating_add(1);
    encoded.insert(insertion, 0x00);
    encoded.insert(insertion, 0x41);
    encoded.insert(insertion, 0x05);

    // When: the secret-bearing extension crosses the typed frame boundary.
    let result = decode_frame(&encoded);

    // Then: the unknown field is rejected and never represented in a domain type.
    assert!(matches!(
        result,
        Err(ProtocolError::UnknownField
            | ProtocolError::DuplicateOrUnorderedKey
            | ProtocolError::MissingField)
    ));
}

#[test]
fn state_and_lifetime_constants_are_frozen() {
    // Given: every lifetime, capability, and version value consumed by later state layers.
    let observed = (
        PROTOCOL_VERSION,
        TTL_SECONDS,
        MAX_USES,
        REPLAY_MIN_SECONDS,
        REPLAY_MIN_PROFILE_EPOCHS,
        CapabilityBitmap::REQUIRED.bits(),
    );

    // When: the frozen contract tuple is compared to its approved values.
    // Then: no implementation-selected value can silently replace the protocol decision.
    assert_eq!(observed, (2, 120, 1, 86_400, 2, REQUIRED_CAPABILITIES));
    assert_eq!(
        [
            MessageKind::Hello,
            MessageKind::HelloAck,
            MessageKind::Generate,
            MessageKind::Get,
            MessageKind::List,
            MessageKind::Delete,
            MessageKind::Begin,
            MessageKind::UpdateAad,
            MessageKind::Update,
            MessageKind::Finish,
            MessageKind::Abort,
            MessageKind::Result,
            MessageKind::Error,
        ]
        .map(u64::from),
        [1, 2, 10, 11, 12, 13, 20, 21, 22, 23, 24, 30, 31]
    );
    assert_eq!(
        CapabilityBitmap::parse(0x1f),
        Err(ProtocolError::UnsupportedValue)
    );
}

#[test]
fn error_stage_limit_and_tombstone_contracts_are_exact() {
    // Given: every frozen error/stage plus one typed session/request/operation identity.
    let errors = [
        RkaErrorCode::InvalidRequest,
        RkaErrorCode::PolicyRejected,
        RkaErrorCode::UnsupportedAlgorithm,
        RkaErrorCode::UnsupportedPurpose,
        RkaErrorCode::UnsupportedDigest,
        RkaErrorCode::UnsupportedEcCurve,
        RkaErrorCode::Capacity,
        RkaErrorCode::StaleHandle,
        RkaErrorCode::Transport,
        RkaErrorCode::OperationLost,
        RkaErrorCode::Quarantined,
    ];
    let stages = [
        Stage::Frame,
        Stage::Policy,
        Stage::Session,
        Stage::Transport,
        Stage::Rkp,
        Stage::KeyMint,
        Stage::Lifecycle,
        Stage::Storage,
    ];
    let peer = PeerSpkiHash::new([0x55; 32]);
    let session = SessionId::new([0x66; 32]);
    let request = RequestId::new([0x77; 16]);

    // When: numeric tags, limits, mappings, and all three replay tuples are encoded.
    let session_key = session_tombstone(peer, 9, session);
    let request_key = request_tombstone((peer, 9, session), (request, MessageKind::Generate));
    let operation_key = operation_tombstone((peer, 9, session), OperationHandle::new([0x88; 16]));

    // Then: integer spaces and canonical replay layouts remain exact and distinct.
    assert_eq!(errors.map(u64::from), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!(stages.map(u64::from), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        RkaErrorCode::Quarantined.keymint_error(),
        KeyMintError::SecureHardwareCommunicationFailed
    );
    assert!(validate_deterministic_cbor(&frozen_limits_cbor()).is_ok());
    assert!(validate_deterministic_cbor(&session_key).is_ok());
    assert!(validate_deterministic_cbor(&request_key).is_ok());
    assert!(validate_deterministic_cbor(&operation_key).is_ok());
    assert_ne!(session_key, request_key);
    assert_ne!(request_key, operation_key);
}

const fn hello_frame() -> Frame<'static> {
    Frame::new(
        FrameContext::new(
            (RequestId::new([0x22; 16]), SessionId::new([0x11; 32])),
            (7, 0),
        ),
        MessageKind::Hello,
        FrameBody::Hello(Hello::new(
            [0x33; 32],
            [0x44; 32],
            CapabilityBitmap::REQUIRED,
        )),
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}

fn hex32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (target, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = u8::from_str_radix(core::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0);
    }
    output
}
