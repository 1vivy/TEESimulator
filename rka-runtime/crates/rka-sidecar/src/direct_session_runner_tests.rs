use std::{
    io,
    net::{SocketAddr, SocketAddrV4, TcpListener},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
};

use rka_protocol::{FrameBody, MessageKind, decode_frame};
use rka_state::PairedActivationRecord;
use rka_transport::peer_spki_hash;

use super::{
    CandidateIterationError, DirectSessionError, DonorIteration, bind_local, read_frame,
    run_candidate_once, run_donor_once,
    tests::{TempState, identities, persist_identity, persist_profile, routed_local_ipv4},
    write_frame,
};
use crate::{
    LifecycleRole, direct_profile::DirectProfile, donor::dispatch_tests::support::Fixture,
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
        self.candidate.0.join("run/sockets/candidate-rka.sock")
    }
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
