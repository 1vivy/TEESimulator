use std::{collections::HashMap, path::PathBuf, sync::Arc};

#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling direct-session runner proof reuses this test fixture"
)]
pub(crate) mod support;

use rka_protocol::{
    Frame, FrameBody, FrameContext, MessageKind, RequestId, SessionId, encode_frame,
    encode_frame_without_transcript, transcript_hash,
};
use rka_state::PairedActivationRecord;

use super::{
    BridgeDonorBroker, CandidateShard, DonorError, DonorRuntime, PairedPolicy, quota::DonorQuota,
    runtime::RuntimeTrust, shard::DurableShardState, state::TranscriptJournal,
};
use crate::candidate::{PairingAdmission, PairingCatalog};

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
    let mut catalog = PairingCatalog::empty();
    catalog
        .admit(PairingAdmission::new(
            (
                pair.peer_spki_hash,
                pair.profile_id_hash,
                pair.profile_epoch,
            ),
            pair.candidate_identity_hash,
        ))
        .unwrap();
    let context = catalog
        .lookup(
            pair.peer_spki_hash,
            pair.profile_id_hash,
            pair.profile_epoch,
        )
        .unwrap();
    let quota = DonorQuota::shared();
    let shard = CandidateShard::durable(
        &context,
        policy,
        DurableShardState {
            trust: RuntimeTrust {
                pair,
                leases: Vec::new(),
            },
            replay_root: root.clone(),
            transcript: TranscriptJournal::open(&root, prior).unwrap(),
            quota: Arc::clone(&quota),
        },
    )
    .unwrap();
    let mut runtime = DonorRuntime {
        shards: HashMap::from([(*context.candidate(), shard)]),
        broker: BridgeDonorBroker::new(root.join("unused.sock").as_path()),
        catalog,
        remote_keys: super::collision::RemoteKeyRegistry::default(),
        state_root: Some(root.clone()),
        local_candidate: Some(context),
        quota,
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
    assert_eq!(
        runtime
            .shards
            .get(context.candidate())
            .unwrap()
            .transcript
            .as_ref()
            .unwrap()
            .committed(),
        Ok(prior)
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_generate_crosses_live_ingress_and_advances_through_each_result()
-> Result<(), Box<dyn std::error::Error>> {
    use rka_protocol::{MessageKind, decode_frame};
    use std::{
        io::{Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    // Given: durable pairing/lease/chain state and a live JVM/root-broker codec endpoint.
    let fixture = support::Fixture::new()?;
    let listener = UnixListener::bind(&fixture.broker_socket)?;
    let broker = thread::spawn(move || -> Result<Vec<Vec<u8>>, String> {
        let mut captured = Vec::new();
        for ordinal in 1..=2 {
            captured.push(support::Fixture::serve_broker(&listener, ordinal)?);
        }
        Ok(captured)
    });
    let ingress =
        super::DonorIngress::bind_for_owner_policy(&fixture.root, fixture.uid, fixture.gid)?;
    let mut runtime = DonorRuntime::open(&fixture.root, &fixture.broker_socket);
    runtime.broker = BridgeDonorBroker::new_authenticated_test(&fixture.broker_socket, 2)?;
    assert!(runtime.is_active());
    let mut prior = fixture.initial_transcript;
    let mut first_result_head = None;

    // When: two canonical Generates use each preceding public RESULT as their chain head.
    for ordinal in 1..=2 {
        let request = fixture.generate_frame(ordinal, prior);
        let mut client = UnixStream::connect(ingress.path())?;
        client.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
        client.write_all(&request)?;
        assert_eq!(
            ingress.serve_once_for_peer_policy(&mut runtime, fixture.uid, fixture.gid)?,
            super::ServeOutcome::Dispatched
        );
        let mut length = [0; 4];
        client.read_exact(&mut length)?;
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        client.read_exact(&mut response)?;
        let public = decode_frame(&response)?;
        assert_eq!(public.kind, MessageKind::Result);
        assert_eq!(
            public.body,
            rka_protocol::FrameBody::Response(&fixture.expected_result_body(ordinal))
        );
        prior = public.transcript_hash;
        if ordinal == 1 {
            first_result_head = Some(prior);
        }
    }

    // Then: lease-derived authority, and no envelope/caller/empty substitute, reached the broker.
    let captured = broker.join().map_err(|_| "broker thread panicked")??;
    assert_eq!(runtime.broker.authenticated_test_exchanges(), 2);
    assert_eq!(
        captured,
        vec![
            support::Fixture::expected_broker_payload(1, fixture.initial_transcript),
            support::Fixture::expected_broker_payload(
                2,
                first_result_head.ok_or("missing first RESULT transcript head")?,
            ),
        ]
    );
    fixture.cleanup()?;
    Ok(())
}

#[test]
fn generate_carrying_a_foreign_candidate_identity_is_rejected_before_any_broker_exchange()
-> Result<(), Box<dyn std::error::Error>> {
    // Given: durable pairing state and a generate frame whose identity is not the paired identity.
    let fixture = support::Fixture::new()?;
    let mut runtime = fixture.runtime(0)?;
    assert!(runtime.is_active());
    let request = fixture.generate_frame_with_lineage(
        1,
        fixture.initial_transcript,
        support::FOREIGN_LINEAGE,
    );

    // When: the donor dispatches that frame.
    let rejected = runtime.dispatch_frame(&request);

    // Then: the trusted paired identity governs and the broker was never reached.
    assert_eq!(rejected, Err(DonorError::IdentityDrift));
    assert_eq!(support::Fixture::authenticated_exchanges(&runtime), 0);
    fixture.cleanup()?;
    Ok(())
}

fn root() -> PathBuf {
    std::env::temp_dir().join(format!("rka-donor-preflight-{}", std::process::id()))
}
