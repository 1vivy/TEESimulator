use std::path::PathBuf;

use rka_protocol::{
    Frame, FrameBody, FrameContext, MessageKind, RequestId, SessionId, encode_frame,
    encode_frame_without_transcript, transcript_hash,
};
use rka_state::PairedActivationRecord;

use super::{
    BridgeDonorBroker, DonorError, DonorRkaService, DonorRuntime, PairedPolicy,
    runtime::RuntimeTrust, state::TranscriptJournal,
};

#[test]
fn rejected_request_never_reserves_the_durable_transcript() {
    // Given
    let root = root();
    let prior = [8; 32];
    let pair = PairedActivationRecord {
        peer_spki_hash: [1; 32],
        profile_id_hash: [2; 32],
        profile_epoch: 3,
        candidate_identity_hash: [4; 32],
        session_id: [5; 32],
        candidate_nonce: [6; 32],
        donor_nonce: [7; 32],
        prior_transcript_hash: prior,
    };
    let policy = PairedPolicy::new(
        pair.peer_spki_hash,
        pair.profile_id_hash,
        pair.profile_epoch,
        pair.candidate_identity_hash,
        [9; 32],
        prior,
    );
    let mut runtime = DonorRuntime {
        service: Some(DonorRkaService::new(policy)),
        broker: BridgeDonorBroker::new(root.join("unused.sock").as_path()),
        trust: Some(RuntimeTrust {
            pair,
            leases: Vec::new(),
        }),
        state_root: Some(root.clone()),
        transcript: Some(TranscriptJournal::open(&root, prior).unwrap()),
    };
    let mut frame = Frame::new(
        FrameContext::new(
            (RequestId::new([10; 16]), SessionId::new(pair.session_id)),
            (pair.profile_epoch, 1),
        ),
        MessageKind::Begin,
        FrameBody::Begin([11; 16]),
    );
    frame.transcript_hash = transcript_hash(&prior, &encode_frame_without_transcript(&frame));

    // When
    let result = runtime.dispatch_frame(&encode_frame(&frame));

    // Then
    assert_eq!(result, Err(DonorError::StaleHandle));
    assert_eq!(runtime.transcript.unwrap().committed(), Ok(prior));
    let _ = std::fs::remove_dir_all(root);
}

fn root() -> PathBuf {
    std::env::temp_dir().join(format!("rka-donor-preflight-{}", std::process::id()))
}
