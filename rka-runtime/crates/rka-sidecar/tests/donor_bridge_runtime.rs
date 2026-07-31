#![allow(missing_docs, reason = "integration tests are behavior-named")]

use rka_sidecar::bridge::{
    BridgeMessage, CandidateBridgeOperation, ExchangeRole, PublicBytes, RequestId, decode_frame,
    encode_frame,
};
use rka_sidecar::donor::{DeleteRequest, DonorError, DonorRuntime};

#[test]
fn donor_bridge_candidate_command_matches_authenticated_jvm_wire_golden()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let command = BridgeMessage::CandidateCommand(
        RequestId::new(0x0102_0304_0506_0708),
        CandidateBridgeOperation::List,
        PublicBytes::bounded(b"abc", 0, 32)?,
    );

    // When
    let encoded = encode_frame(&command, ExchangeRole::DonorRequest)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::DonorRequest)?;

    // Then
    assert_eq!(encoded.as_slice(), candidate_command_golden());
    assert_eq!(decoded, command);
    Ok(())
}

const fn candidate_command_golden() -> &'static [u8] {
    &[
        0x52, 0x4b, 0x42, 0x31, 0x01, 0x01, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x61,
        0x62, 0x63,
    ]
}

#[test]
fn production_donor_runtime_is_closed_until_authenticated_pairing() {
    let mut runtime = DonorRuntime::new(std::path::Path::new("/unused/broker.sock"));
    let request = DeleteRequest::new(
        [1; 16],
        rka_sidecar::donor::AccessContext {
            peer_spki_hash: [2; 32],
            profile_id_hash: [3; 32],
            profile_epoch: 4,
            session_id: [5; 32],
            candidate_nonce: [6; 32],
            donor_nonce: [7; 32],
            candidate_identity_hash: [8; 32],
            now_ms: 9,
        },
        [10; 16],
    );

    assert_eq!(runtime.get(request), Err(DonorError::Unpaired));
}

#[test]
fn donor_role_entry_constructs_the_production_runtime() {
    let entry = include_str!("../src/main.rs");

    assert!(entry.contains("DonorRuntime::new"));
    assert!(entry.contains("LifecycleRole::Donor"));
}
