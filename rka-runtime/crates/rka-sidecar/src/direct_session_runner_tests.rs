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
};

use rka_protocol::{FrameBody, MessageKind, decode_frame};
use rka_state::PairedActivationRecord;
use rka_transport::peer_spki_hash;

use super::{
    CandidateIterationError, DirectSessionError, DonorIteration, bind_local, candidate_server,
    connect_bound, donor_client, read_frame, run_candidate_once, run_donor_once,
    tests::{TempState, identities, persist_identity, persist_profile, routed_local_ipv4},
    write_frame,
};
use crate::{
    LifecycleRole,
    candidate::{PairingAdmission, PairingCatalog},
    direct_profile::DirectProfile,
    donor::dispatch_tests::support::Fixture,
    provisioning_io::FileStateStore,
};

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
    let donor = donor_client(&fixture.donor.root, &fixture.donor_profile)?;
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
