//! Kotlin-to-Rust RKB1 byte interoperation tests.

use std::{collections::BTreeMap, error::Error};

use rka_sidecar::bridge::{
    BridgeMessage, CandidateBridgeOperation, ExchangeRole, Hash32, PublicBytes, RequestId,
    decode_frame, encode_frame, expected_response_tag,
};
use rka_sidecar::candidate::{PairingAdmission, PairingCatalog};

const GOLDENS: &str = include_str!("fixtures/bridge-kotlin-goldens-v1.txt");
const CANDIDATE_ID_OFFSET: usize = 25;

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(*pair.first().ok_or("fixture high byte")?)
                .to_digit(16)
                .ok_or("fixture high hex")?;
            let low = char::from(*pair.get(1).ok_or("fixture low byte")?)
                .to_digit(16)
                .ok_or("fixture low hex")?;
            Ok(u8::try_from((high << 4) | low)?)
        })
        .collect()
}

fn fixtures() -> Result<BTreeMap<&'static str, Vec<u8>>, Box<dyn Error>> {
    GOLDENS
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('=').ok_or("fixture delimiter")?;
            Ok((name, decode_hex(value)?))
        })
        .collect()
}

fn role_for(name: &str) -> ExchangeRole {
    if name.ends_with("donor_request") {
        ExchangeRole::DonorRequest
    } else if name.ends_with("donor_response") {
        ExchangeRole::DonorResponse
    } else if name.ends_with("candidate_request") {
        ExchangeRole::CandidateRequest
    } else {
        ExchangeRole::CandidateResponse
    }
}

#[test]
fn bridge_golden_interop_decodes_and_reencodes_every_kotlin_dto() -> Result<(), Box<dyn Error>> {
    let vectors = fixtures()?;
    assert_eq!(vectors.len(), 14);
    for (name, bytes) in vectors {
        let role = role_for(name);
        let message = decode_frame(&bytes, role)?;
        assert_eq!(message.request_id(), RequestId::new(0x0102_0304_0506_0708));
        let encoded = encode_frame(&message, role)?;
        assert_eq!(encoded.as_slice(), bytes.as_slice(), "vector {name}");
    }
    Ok(())
}

#[test]
fn bridge_golden_interop_correlates_exact_response_kinds() -> Result<(), Box<dyn Error>> {
    let vectors = fixtures()?;
    let request = decode_frame(
        vectors
            .get("public_key_request_donor_request")
            .ok_or("request fixture")?,
        ExchangeRole::DonorRequest,
    )?;
    let update = decode_frame(
        vectors
            .get("update_request_candidate_request")
            .ok_or("update fixture")?,
        ExchangeRole::CandidateRequest,
    )?;
    let cancel = decode_frame(
        vectors
            .get("cancel_donor_request")
            .ok_or("cancel fixture")?,
        ExchangeRole::DonorRequest,
    )?;

    assert_eq!(expected_response_tag(&request)?, 2);
    assert_eq!(expected_response_tag(&update)?, 4);
    assert_eq!(expected_response_tag(&cancel)?, 5);
    assert!(matches!(request, BridgeMessage::PublicKeyRequest(..)));
    Ok(())
}

#[test]
fn candidate_command_encodes_the_trusted_candidate_id() -> Result<(), Box<dyn Error>> {
    // Given
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission::new(
        ([0x11; 32], [0x22; 32], 7),
        [0x33; 32],
    ))?;
    let context = catalog.lookup([0x11; 32], [0x22; 32], 7)?;
    let candidate_id = *context.candidate().as_bytes();
    let command = BridgeMessage::CandidateCommand(
        RequestId::new(0x0102_0304_0506_0708),
        CandidateBridgeOperation::List,
        Hash32::new(candidate_id),
        PublicBytes::bounded(b"abc", 0, 32)?,
    );

    // When
    let encoded = encode_frame(&command, ExchangeRole::DonorRequest)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::DonorRequest)?;

    // Then
    assert_eq!(
        encoded
            .as_slice()
            .get(CANDIDATE_ID_OFFSET..CANDIDATE_ID_OFFSET + candidate_id.len())
            .ok_or("candidate id offset")?,
        candidate_id
    );
    assert_eq!(decoded, command);
    Ok(())
}
