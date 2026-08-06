// allow: SIZE_OK — one end-to-end runner matrix shares live donor/candidate socket fixtures.
use std::{
    cell::Cell,
    fs, io,
    net::{SocketAddr, SocketAddrV4, TcpListener},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::mpsc,
    time::Duration,
};

use rka_protocol::{FrameBody, MessageKind, decode_frame};
use rka_state::PairedActivationRecord;
use rka_transport::peer_spki_hash;

use super::{
    CandidateIterationError, DirectSessionError, DonorIteration, authenticated_profile, bind_local,
    candidate_diagnostic, candidate_diagnostic_path, candidate_local_socket_path, candidate_server,
    connect_bound, donor_client, local_socket_path, read_frame, resolve_donor_bindings,
    run_candidate_once, run_donor_once,
    tests::{TempState, identities, persist_identity, persist_profile, routed_local_ipv4},
    write_frame,
};

#[test]
fn each_candidate_gets_its_own_diagnostic_file_and_local_broker_socket()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let state = TempState::new("candidate-runtime-paths")?;
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission::new(
        ([0x41; 32], [0x51; 32], 9),
        [0x61; 32],
    ))?;
    catalog.admit(PairingAdmission::new(
        ([0x42; 32], [0x52; 32], 9),
        [0x62; 32],
    ))?;
    let candidate_a = catalog.lookup([0x41; 32], [0x51; 32], 9)?;
    let candidate_b = catalog.lookup([0x42; 32], [0x52; 32], 9)?;

    // When
    candidate_diagnostic(&state.0, candidate_a.candidate(), "candidate-a-ready");
    candidate_diagnostic(&state.0, candidate_b.candidate(), "candidate-b-ready");
    let diagnostic_a = candidate_diagnostic_path(&state.0, candidate_a.candidate());
    let diagnostic_b = candidate_diagnostic_path(&state.0, candidate_b.candidate());
    let socket_a = candidate_local_socket_path(&state.0, candidate_a.candidate());
    let socket_b = candidate_local_socket_path(&state.0, candidate_b.candidate());

    // Then
    assert_ne!(diagnostic_a, diagnostic_b);
    assert_ne!(socket_a, socket_b);
    assert_eq!(fs::read_to_string(diagnostic_a)?, "candidate-a-ready\n");
    assert_eq!(fs::read_to_string(diagnostic_b)?, "candidate-b-ready\n");
    Ok(())
}
use crate::{
    LifecycleRole,
    candidate::{CandidateLayout, PairingAdmission, PairingCatalog},
    direct_profile::{DirectProfile, DonorProfileSource},
    donor::{DonorError, actor::CandidateActor, dispatch_tests::support::Fixture},
    provisioning_io::FileStateStore,
};

#[test]
fn legacy_single_candidate_binding_uses_the_global_state_and_broker_socket()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let state = TempState::new("legacy-donor-binding")?;
    fs::create_dir_all(state.0.join("profiles/direct.d"))?;
    let peer_pin = [0x51; 32];
    let profile = persist_profile(
        &state.0,
        (LifecycleRole::Donor, routed_local_ipv4()?, peer_pin),
    )?;
    let pair = PairedActivationRecord {
        peer_spki_hash: peer_pin,
        profile_id_hash: [0x52; 32],
        profile_epoch: profile.epoch,
        candidate_identity_hash: [0x53; 32],
        session_id: [0x54; 32],
        candidate_nonce: [0x55; 32],
        donor_nonce: [0x56; 32],
        prior_transcript_hash: [0x57; 32],
    };
    pair.persist(&FileStateStore::new(&state.0))?;

    // When
    let bindings = resolve_donor_bindings(&state.0, DonorProfileSource::Legacy, vec![profile])?;

    // Then
    assert_eq!(bindings.len(), 1);
    let binding = bindings.first().ok_or("legacy binding missing")?;
    assert_eq!(binding.runtime_root, state.0);
    assert_eq!(
        local_socket_path(&binding.runtime_root),
        binding.runtime_root.join("run/sockets/broker.sock")
    );
    assert_eq!(
        binding.authenticated.candidate().as_bytes(),
        &pair.candidate_identity_hash
    );
    Ok(())
}

#[test]
fn indexed_binding_rejects_missing_candidate_state_instead_of_using_global_state()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let state = TempState::new("indexed-donor-binding")?;
    let peer_pin = [0x61; 32];
    let profile = persist_profile(
        &state.0,
        (LifecycleRole::Donor, routed_local_ipv4()?, peer_pin),
    )?;
    let pair = PairedActivationRecord {
        peer_spki_hash: peer_pin,
        profile_id_hash: [0x62; 32],
        profile_epoch: profile.epoch,
        candidate_identity_hash: [0x63; 32],
        session_id: [0x64; 32],
        candidate_nonce: [0x65; 32],
        donor_nonce: [0x66; 32],
        prior_transcript_hash: [0x67; 32],
    };
    pair.persist(&FileStateStore::new(&state.0))?;
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission {
        peer_spki_hash: pair.peer_spki_hash,
        profile_id_hash: pair.profile_id_hash,
        profile_epoch: pair.profile_epoch,
        candidate_identity_hash: pair.candidate_identity_hash,
    })?;
    catalog.persist(&state.0)?;
    let candidate = catalog.lookup_identity(pair.candidate_identity_hash)?;
    let missing = CandidateLayout::new(&state.0, candidate.candidate());
    assert!(!missing.root().exists());

    // When
    let result = resolve_donor_bindings(&state.0, DonorProfileSource::Indexed, vec![profile]);

    // Then
    assert!(matches!(result, Err(DirectSessionError::State)));
    assert!(!missing.root().exists());
    Ok(())
}

#[test]
fn a_slow_candidate_does_not_block_another_candidates_frame_from_being_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission::new(
        ([0x11; 32], [0x21; 32], 1),
        [0x31; 32],
    ))?;
    catalog.admit(PairingAdmission::new(
        ([0x12; 32], [0x22; 32], 1),
        [0x32; 32],
    ))?;
    let slow_candidate = *catalog.lookup([0x11; 32], [0x21; 32], 1)?.candidate();
    let fast_candidate = *catalog.lookup([0x12; 32], [0x22; 32], 1)?.candidate();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel();
    let accepted_a = accepted_tx.clone();
    let candidate_a = CandidateActor::spawn(slow_candidate, move |frame| {
        accepted_a.send(frame).map_err(|_| DonorError::Broker)?;
        gate_rx.recv().map_err(|_| DonorError::Broker)?;
        Ok(b"candidate-a-response".to_vec())
    })?;
    let candidate_b = CandidateActor::spawn(fast_candidate, move |frame| {
        accepted_tx.send(frame).map_err(|_| DonorError::Broker)?;
        Ok(b"candidate-b-response".to_vec())
    })?;
    let (result_a_tx, result_a_rx) = mpsc::channel();
    let slow_supervisor = std::thread::spawn(move || {
        result_a_tx.send(candidate_a.dispatch(&slow_candidate, b"candidate-a-frame".to_vec()))
    });
    assert_eq!(accepted_rx.recv()?, b"candidate-a-frame");
    let (result_b_tx, result_b_rx) = mpsc::channel();

    // When
    let fast_supervisor = std::thread::spawn(move || {
        result_b_tx.send(candidate_b.dispatch(&fast_candidate, b"candidate-b-frame".to_vec()))
    });
    let accepted_b = accepted_rx.recv_timeout(Duration::from_secs(1))?;
    let response_b = result_b_rx.recv_timeout(Duration::from_secs(1))??;

    // Then
    assert_eq!(accepted_b, b"candidate-b-frame");
    assert_eq!(response_b, b"candidate-b-response");
    assert!(matches!(
        result_a_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    gate_tx.send(())?;
    assert_eq!(result_a_rx.recv()??, b"candidate-a-response");
    slow_supervisor
        .join()
        .map_err(|_| "candidate A supervisor failed")??;
    fast_supervisor
        .join()
        .map_err(|_| "candidate B supervisor failed")??;
    Ok(())
}

#[test]
fn candidate_actor_rejects_a_frame_for_another_candidate() -> Result<(), Box<dyn std::error::Error>>
{
    // Given
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission::new(
        ([0x13; 32], [0x23; 32], 1),
        [0x33; 32],
    ))?;
    catalog.admit(PairingAdmission::new(
        ([0x14; 32], [0x24; 32], 1),
        [0x34; 32],
    ))?;
    let actor_candidate = *catalog.lookup([0x13; 32], [0x23; 32], 1)?.candidate();
    let foreign_candidate = *catalog.lookup([0x14; 32], [0x24; 32], 1)?.candidate();
    let actor = CandidateActor::spawn(actor_candidate, |_| Ok(Vec::new()))?;

    // When
    let result = actor.dispatch(&foreign_candidate, b"wrong-candidate".to_vec());

    // Then
    assert_eq!(result, Err(DonorError::Unpaired));
    Ok(())
}

struct RunnerFixture {
    donor: Fixture,
    candidate: TempState,
    donor_profile: DirectProfile,
    candidate_profile: DirectProfile,
    pair: PairedActivationRecord,
    local: std::net::Ipv4Addr,
}

impl RunnerFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let local = routed_local_ipv4()?;
        let candidate = TempState::new("candidate-runner")?;
        let (root, donor_certificate, donor_key, candidate_certificate, candidate_key) =
            identities()?;
        let donor_pin = peer_spki_hash(&donor_certificate)?;
        let candidate_pin = peer_spki_hash(&candidate_certificate)?;
        let donor = Fixture::new_with_peer(candidate_pin)?;
        persist_identity(&donor.root, (&donor_certificate, &donor_key, &root))?;
        persist_identity(
            &candidate.0,
            (&candidate_certificate, &candidate_key, &root),
        )?;
        let pair = PairedActivationRecord::load(&FileStateStore::new(&donor.root))?;
        PairedActivationRecord {
            peer_spki_hash: donor_pin,
            ..pair
        }
        .persist(&FileStateStore::new(&candidate.0))?;
        let donor_profile =
            persist_profile(&donor.root, (LifecycleRole::Donor, local, candidate_pin))?;
        let candidate_profile =
            persist_profile(&candidate.0, (LifecycleRole::Candidate, local, donor_pin))?;
        let mut catalog = PairingCatalog::empty();
        catalog.admit(PairingAdmission {
            peer_spki_hash: candidate_pin,
            profile_id_hash: pair.profile_id_hash,
            profile_epoch: donor_profile.epoch,
            candidate_identity_hash: pair.candidate_identity_hash,
        })?;
        catalog.persist(&donor.root)?;
        Ok(Self {
            donor,
            candidate,
            donor_profile,
            candidate_profile,
            pair,
            local,
        })
    }

    fn network(&self) -> Result<(TcpListener, SocketAddrV4), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddrV4::new(self.local, 0))?;
        let remote = match listener.local_addr()? {
            SocketAddr::V4(remote) => remote,
            SocketAddr::V6(_) => return Err("unexpected IPv6 listener".into()),
        };
        Ok((listener, remote))
    }

    fn candidate_socket(&self) -> PathBuf {
        self.candidate.0.join("run/sockets/broker.sock")
    }
}

#[test]
fn donor_dispatch_receives_the_catalog_resolved_candidate_for_the_selected_profile()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = RunnerFixture::new()?;
    let candidate_a = fixture.pair.candidate_identity_hash.map(|byte| byte ^ 0xff);
    let mut catalog = PairingCatalog::empty();
    catalog.admit(PairingAdmission {
        peer_spki_hash: fixture.donor_profile.peer_pin.map(|byte| byte ^ 0xff),
        profile_id_hash: fixture.pair.profile_id_hash.map(|byte| byte ^ 0xff),
        profile_epoch: fixture.donor_profile.epoch,
        candidate_identity_hash: candidate_a,
    })?;
    catalog.admit(PairingAdmission {
        peer_spki_hash: fixture.donor_profile.peer_pin,
        profile_id_hash: fixture.pair.profile_id_hash,
        profile_epoch: fixture.donor_profile.epoch,
        candidate_identity_hash: fixture.pair.candidate_identity_hash,
    })?;
    catalog.persist(&fixture.donor.root)?;
    let (network, remote) = fixture.network()?;
    let candidate = candidate_server(&fixture.candidate.0, &fixture.candidate_profile)?;
    let worker = std::thread::spawn(move || {
        let (socket, _) = network.accept().map_err(|_| {
            rka_transport::CandidateExchangeError::PreDispatch(rka_transport::TlsError::Io)
        })?;
        candidate.exchange(socket, b"candidate-b-request")
    });
    let authenticated = authenticated_profile(&fixture.donor.root, &fixture.donor_profile)?;
    let binding = super::DonorProfileBinding {
        profile: fixture.donor_profile,
        authenticated,
        runtime_root: fixture.donor.root.clone(),
    };
    let donor = donor_client(&fixture.donor.root, &binding)?;
    let observed = Cell::new(None);

    // When
    let result = donor.serve_once(
        connect_bound(fixture.local, remote, std::time::Duration::from_secs(2))?,
        |authenticated, request| {
            observed.set(Some(*authenticated.candidate().as_bytes()));
            assert_eq!(request, b"candidate-b-request");
            Ok(b"candidate-b-response".to_vec())
        },
    );

    // Then
    result?;
    assert_eq!(observed.get(), Some(fixture.pair.candidate_identity_hash));
    assert_ne!(observed.get(), Some(candidate_a));
    assert_eq!(
        worker.join().map_err(|_| "candidate thread failed")??,
        b"candidate-b-response"
    );
    fixture.donor.cleanup()?;
    Ok(())
}

#[test]
fn candidate_local_bridge_reclaims_the_production_broker_socket()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let state = TempState::new("candidate-local-bridge")?;
    let directory = state.0.join("run/sockets");
    fs::create_dir_all(&directory)?;
    let socket = directory.join("broker.sock");
    drop(UnixListener::bind(&socket)?);

    // When
    let _listener = bind_local(&state.0)?;

    // Then
    let metadata = fs::metadata(&socket)?;
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(&directory)?.permissions().mode() & 0o777,
        0o700
    );
    assert!(UnixStream::connect(&socket).is_ok());
    assert!(!directory.join("candidate-rka.sock").exists());
    Ok(())
}

#[test]
fn production_runner_retries_pre_dispatch_then_dispatches_broker_once()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = RunnerFixture::new()?;
    let mut runtime = fixture.donor.runtime(1)?;
    let broker_listener = UnixListener::bind(&fixture.donor.broker_socket)?;
    let broker = std::thread::spawn(move || Fixture::serve_broker(&broker_listener, 1));
    let (network, remote) = fixture.network()?;
    let local_broker = bind_local(&fixture.candidate.0)?;
    let candidate_socket = fixture.candidate_socket();
    let candidate_root = fixture.candidate.0.clone();
    let candidate_profile = fixture.candidate_profile;
    let candidate = std::thread::spawn(move || {
        run_candidate_once((&network, &local_broker, &candidate_root, &candidate_profile))
    });
    let mut client = UnixStream::connect(candidate_socket)?;
    let request = fixture
        .donor
        .generate_frame(1, fixture.donor.initial_transcript);
    write_frame(&mut client, &request)?;
    let mut wrong_pair = fixture.pair;
    wrong_pair.session_id = [0xee; 32];
    wrong_pair.persist(&FileStateStore::new(&fixture.donor.root))?;

    // When
    let first = run_donor_once(
        (&mut runtime, &fixture.donor.root, &fixture.donor_profile),
        remote,
    )?;
    fixture
        .pair
        .persist(&FileStateStore::new(&fixture.donor.root))?;
    let second = run_donor_once(
        (&mut runtime, &fixture.donor.root, &fixture.donor_profile),
        remote,
    )?;
    let response = read_frame(&mut client)?;

    // Then
    assert_eq!(first, DonorIteration::Retry);
    assert_eq!(second, DonorIteration::Served);
    assert_eq!(Fixture::authenticated_exchanges(&runtime), 1);
    assert_eq!(
        candidate
            .join()
            .map_err(|_| "candidate thread failed")??
            .accepted_connections,
        2
    );
    let public = decode_frame(&response)?;
    assert_eq!(public.kind, MessageKind::Result);
    assert_eq!(
        public.body,
        FrameBody::Response(&fixture.donor.expected_result_body(1))
    );
    assert_eq!(
        broker.join().map_err(|_| "broker thread failed")??,
        Fixture::expected_broker_payload(1, fixture.donor.initial_transcript)
    );
    fixture.donor.cleanup()?;
    Ok(())
}

#[test]
fn production_runner_stops_after_ambiguous_dispatch_without_second_connection()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let fixture = RunnerFixture::new()?;
    let mut runtime = fixture.donor.runtime(1)?;
    let broker_listener = UnixListener::bind(&fixture.donor.broker_socket)?;
    let broker =
        std::thread::spawn(move || Fixture::capture_broker_without_response(&broker_listener));
    let (network, remote) = fixture.network()?;
    let network_probe = network.try_clone()?;
    let local_broker = bind_local(&fixture.candidate.0)?;
    let candidate_socket = fixture.candidate_socket();
    let candidate_root = fixture.candidate.0.clone();
    let candidate_profile = fixture.candidate_profile;
    let candidate = std::thread::spawn(move || {
        run_candidate_once((&network, &local_broker, &candidate_root, &candidate_profile))
    });
    let mut client = UnixStream::connect(candidate_socket)?;
    write_frame(
        &mut client,
        &fixture
            .donor
            .generate_frame(1, fixture.donor.initial_transcript),
    )?;

    // When
    let donor_result = run_donor_once(
        (&mut runtime, &fixture.donor.root, &fixture.donor_profile),
        remote,
    );
    let candidate_result = candidate.join().map_err(|_| "candidate thread failed")?;

    // Then
    assert!(matches!(donor_result, Err(DirectSessionError::Ambiguous)));
    assert_eq!(Fixture::authenticated_exchanges(&runtime), 1);
    assert!(matches!(
        candidate_result,
        Err(CandidateIterationError {
            error: DirectSessionError::Ambiguous,
            accepted_connections: 1,
        })
    ));
    assert!(matches!(
        read_frame(&mut client),
        Err(DirectSessionError::Io)
    ));
    assert_eq!(
        broker.join().map_err(|_| "broker thread failed")??,
        Fixture::expected_broker_payload(1, fixture.donor.initial_transcript)
    );
    network_probe.set_nonblocking(true)?;
    assert!(matches!(
        network_probe.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    fixture.donor.cleanup()?;
    Ok(())
}
