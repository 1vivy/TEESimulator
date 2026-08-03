//! Pinned-mTLS synthetic lease request codec coverage.

use rka_sidecar::bridge::{
    BridgeMessage, ExchangeRole, Hash32, PublicBytes, RequestId, SecretBytes, decode_frame,
    encode_frame,
};

#[test]
fn candidate_issue_request_and_response_round_trip_without_debug_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let private_key = vec![0x5a; 121];
    let request = BridgeMessage::SyntheticLeaseIssueRequest {
        request_id: RequestId::new(91),
        candidate_nonce: Hash32::new([1; 32]),
        profile_id_hash: Hash32::new([2; 32]),
        requested_epoch: 4,
        private_key_pkcs8: SecretBytes::bounded(&private_key, 4_096)?,
        expected_spki: PublicBytes::bounded(&[3; 91], 1, 65_536)?,
        challenge: PublicBytes::bounded(&[4; 32], 16, 64)?,
        aaid: PublicBytes::bounded(&[5; 32], 1, 131_072)?,
        certificate_not_before_millis: 1_700_000_000_000,
        certificate_not_after_millis: 1_700_604_800_000,
    };
    let encoded = encode_frame(&request, ExchangeRole::CandidateRequest)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::CandidateRequest)?;
    assert_eq!(decoded, request);
    assert!(!format!("{decoded:?}").contains("5a5a"));

    let response = BridgeMessage::SyntheticLeaseIssueResponse {
        request_id: RequestId::new(91),
        lease_epoch: 4,
        certificate_chain: vec![
            PublicBytes::bounded(&[0x30, 1], 1, 65_536)?,
            PublicBytes::bounded(&[0x30, 2], 1, 65_536)?,
        ],
    };
    let encoded = encode_frame(&response, ExchangeRole::CandidateResponse)?;
    assert_eq!(
        decode_frame(encoded.as_slice(), ExchangeRole::CandidateResponse)?,
        response
    );
    Ok(())
}

#[test]
fn lease_issue_tags_are_rejected_by_legacy_bridge_directions()
-> Result<(), Box<dyn std::error::Error>> {
    let request = BridgeMessage::SyntheticLeaseIssueRequest {
        request_id: RequestId::new(92),
        candidate_nonce: Hash32::new([1; 32]),
        profile_id_hash: Hash32::new([2; 32]),
        requested_epoch: 0,
        private_key_pkcs8: SecretBytes::bounded(&[7; 121], 4_096)?,
        expected_spki: PublicBytes::bounded(&[3; 91], 1, 65_536)?,
        challenge: PublicBytes::bounded(&[4; 32], 16, 64)?,
        aaid: PublicBytes::bounded(&[5; 32], 1, 131_072)?,
        certificate_not_before_millis: 1,
        certificate_not_after_millis: 2,
    };

    assert!(encode_frame(&request, ExchangeRole::DonorRequest).is_err());
    assert!(encode_frame(&request, ExchangeRole::DonorResponse).is_err());
    Ok(())
}
