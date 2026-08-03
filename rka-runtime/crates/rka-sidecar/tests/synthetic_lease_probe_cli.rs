//! Root-only synthetic lease import probe coverage.

use std::process::Command;

use rka_sidecar::bridge::{
    BridgeMessage, ExchangeRole, Hash32, PublicBytes, RequestId, SecretBytes, decode_frame,
    encode_frame,
};

#[test]
fn local_probe_frame_is_bounded_round_trippable_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = vec![0x5a; 121];
    let request = BridgeMessage::SyntheticLeaseProbeRequest {
        request_id: RequestId::new(71),
        rkp_handle: Hash32::new([2; 32]),
        private_key_pkcs8: SecretBytes::bounded(&pkcs8, 4096)?,
        expected_spki: PublicBytes::bounded(&[3; 91], 1, 65_536)?,
        challenge: PublicBytes::bounded(&[4; 32], 16, 64)?,
        aaid: PublicBytes::bounded(&[5; 16], 1, 131_072)?,
        certificate_not_before_millis: 1_700_000_000_000,
        certificate_not_after_millis: 1_700_604_800_000,
        certificate_chain: vec![
            PublicBytes::bounded(&[0x30, 0], 1, 65_536)?,
            PublicBytes::bounded(&[0x30, 1], 1, 65_536)?,
        ],
    };

    let encoded = encode_frame(&request, ExchangeRole::DonorRequest)?;
    let decoded = decode_frame(encoded.as_slice(), ExchangeRole::DonorRequest)?;

    assert_eq!(decoded, request);
    let debug = format!("{decoded:?}");
    assert!(!debug.contains("5a5a"));
    assert!(!debug.contains("private_key_pkcs8"));
    assert!(debug.contains("tag"));
    Ok(())
}

#[test]
fn command_without_private_root_context_fails_with_one_fixed_status()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("synthetic-lease-probe")
        .env_remove("RKA_STATE_ROOT")
        .env_remove("RKA_DONOR_SOCKET")
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"synthetic_lease_probe_status=invalid_context\n"
    );
    Ok(())
}
