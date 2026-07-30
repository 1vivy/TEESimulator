//! Hostile RKB1 frame regression tests.

use std::panic::catch_unwind;

use rka_sidecar::bridge::{BridgeError, ExchangeRole, decode_frame};

const GOLDEN: &[u8] = &[
    0x52, 0x4b, 0x42, 0x31, 1, 1, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 21, 0, 0, 0, 0, 2, 0, 0,
    0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

fn changed(index: usize, value: u8) -> Vec<u8> {
    let mut frame = GOLDEN.to_vec();
    if let Some(byte) = frame.get_mut(index) {
        *byte = value;
    }
    frame
}

#[test]
fn bridge_rejects_adversarial_frames_without_panicking() {
    let cases = [
        Vec::new(),
        GOLDEN.get(..23).unwrap_or_default().to_vec(),
        changed(0, 0),
        changed(4, 2),
        changed(5, 2),
        changed(6, 0xff),
        changed(7, 1),
        changed(20, 1),
        {
            let mut trailing = GOLDEN.to_vec();
            trailing.push(0);
            trailing
        },
    ];
    for frame in cases {
        let result = catch_unwind(|| decode_frame(&frame, ExchangeRole::DonorRequest));
        assert!(result.is_ok(), "peer bytes must never panic");
        assert!(result.is_ok_and(|decoded| decoded.is_err()));
    }
}

#[test]
fn bridge_rejects_adversarial_frames_before_oversized_body_allocation() {
    let mut oversized = GOLDEN.get(..24).unwrap_or_default().to_vec();
    if let Some(length) = oversized.get_mut(16..20) {
        length.copy_from_slice(&1_048_577_u32.to_be_bytes());
    }
    assert_eq!(
        decode_frame(&oversized, ExchangeRole::DonorRequest),
        Err(BridgeError::FrameTooLarge)
    );
}

#[test]
fn bridge_rejects_adversarial_frames_with_type_confusion() {
    let response_as_request = changed(6, 2);
    assert_eq!(
        decode_frame(&response_as_request, ExchangeRole::DonorRequest),
        Err(BridgeError::UnexpectedTag)
    );
}

#[test]
fn bridge_rejects_adversarial_frames_across_deterministic_hostile_mutations() {
    for index in 0..GOLDEN.len() {
        for mask in [1_u8, 0x80, 0xff] {
            let original = GOLDEN.get(index).copied().unwrap_or_default();
            let frame = changed(index, original ^ mask);
            let result = catch_unwind(|| decode_frame(&frame, ExchangeRole::DonorRequest));
            assert!(result.is_ok());
        }
    }
}

#[test]
fn bridge_rejects_adversarial_frames_for_zero_unknown_reserved_and_concat() {
    let mut empty = GOLDEN.to_vec();
    if let Some(length) = empty.get_mut(16..20) {
        length.fill(0);
    }
    assert_eq!(
        decode_frame(&empty, ExchangeRole::DonorRequest),
        Err(BridgeError::EmptyFrame)
    );
    let mut concatenated = GOLDEN.to_vec();
    concatenated.extend_from_slice(GOLDEN);
    assert_eq!(
        decode_frame(&concatenated, ExchangeRole::DonorRequest),
        Err(BridgeError::NonCanonical)
    );
}
