use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair as RcgenKeyPair, KeyUsagePurpose, PublicKeyData,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as RingKeyPair},
};
use rka_protocol::{
    MessageKind, PeerSpkiHash, RequestId, RkaErrorCode, SessionId, Stage, request_tombstone,
};
use rka_state::{ReplayManager, StateError, StateStore, TombstoneTime};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

use super::{
    AdmissionBinding, AuditChain, AuditEntry, ClientPeer, CsRng, Endpoint, PairedProfile,
    PinnedTlsClient, PinnedTlsServer, ProfileError, ProfileInput, ProfileRotation, ReceiptContext,
    ReceiptVerifier, RequestContext, ResponseContext, Role, ServerPeer, SessionError,
    SessionLifecycle, SessionManager, SessionScope, TlsAdmission, TlsCredentials, TlsError,
    TransportKind, peer_spki_hash,
};
use crate::tls_io::{Deadline, TlsStream, read_frame};
use zeroize::Zeroizing;

#[derive(Debug)]
struct MemoryStore {
    records: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    fail_replace: bool,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            fail_replace: false,
        }
    }
}

impl StateStore for MemoryStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = self
            .records
            .lock()
            .map_err(|_| StateError::Storage)?
            .get(key)
            .cloned()
            .ok_or(StateError::Missing)?;
        let maximum = output.len();
        let target = output
            .get_mut(..value.len())
            .ok_or(StateError::RecordTooLarge {
                actual: value.len(),
                maximum,
            })?;
        target.copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        if self.fail_replace {
            return Err(StateError::Storage);
        }
        self.records
            .lock()
            .map_err(|_| StateError::Storage)?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

struct RawTlsStream(TcpStream);

impl Read for RawTlsStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(output)
    }
}

impl Write for RawTlsStream {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.0.write(input)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl TlsStream for RawTlsStream {
    fn socket(&self) -> &TcpStream {
        &self.0
    }

    fn read_once(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.read(output)
    }

    fn write_once(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.write(input)
    }

    fn wants_flush(&self) -> bool {
        false
    }

    fn flush_once(&mut self) -> std::io::Result<usize> {
        self.flush().map(|()| 1)
    }
}

struct TestCertificate {
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    pin: [u8; 32],
}

impl TestCertificate {
    fn identity(&self) -> TlsCredentials {
        TlsCredentials::new(
            self.chain.clone(),
            PrivatePkcs8KeyDer::from(self.key.clone()).into(),
        )
    }
}

struct TestPki {
    root: CertificateDer<'static>,
    server: TestCertificate,
    client: TestCertificate,
}

fn test_pki() -> Result<TestPki, Box<dyn std::error::Error>> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca_key = RcgenKeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let server = leaf(&issuer, true)?;
    let client = leaf(&issuer, false)?;
    Ok(TestPki {
        root: ca.der().clone(),
        server,
        client,
    })
}

fn leaf(
    issuer: &Issuer<'_, RcgenKeyPair>,
    server: bool,
) -> Result<TestCertificate, Box<dyn std::error::Error>> {
    let names = if server {
        vec!["localhost".to_owned()]
    } else {
        vec!["candidate.invalid".to_owned()]
    };
    let mut params = CertificateParams::new(names)?;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    });
    let key = RcgenKeyPair::generate()?;
    let pin = rka_protocol::sha256(&key.subject_public_key_info());
    let certificate = params.signed_by(&key, issuer)?;
    Ok(TestCertificate {
        chain: vec![certificate.der().clone()],
        key: key.serialize_der(),
        pin,
    })
}

fn binding() -> AdmissionBinding {
    AdmissionBinding {
        profile_id: [1; 32],
        session_id: [2; 32],
        candidate_nonce: [3; 32],
        transcript_hash: [4; 32],
    }
}

fn connected_pair() -> Result<(TcpStream, TcpStream), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let client = TcpStream::connect(address)?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

#[test]
fn pinned_tls_session() -> Result<(), Box<dyn std::error::Error>> {
    let pki = test_pki()?;
    let server_leaf = pki.server.chain.first().ok_or("missing server leaf")?;
    assert_eq!(peer_spki_hash(server_leaf)?, pki.server.pin);
    let trust = vec![pki.root.clone()];
    let name = ServerName::try_from("localhost".to_owned())?;
    let client = PinnedTlsClient::new(
        pki.client.identity(),
        ClientPeer::new(trust.clone(), name, pki.server.pin),
        TlsAdmission::new(binding(), Duration::from_secs(2)),
    )?;
    let server = PinnedTlsServer::new(
        pki.server.identity(),
        &ServerPeer::new(trust, pki.client.pin),
        TlsAdmission::new(binding(), Duration::from_secs(2)),
    )?;
    let (client_socket, server_socket) = connected_pair()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let server_handled = Arc::clone(&handled);
    let worker = std::thread::spawn(move || {
        server.serve_once(server_socket, |request| {
            server_handled.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request, b"RKA-v2-request");
            Ok(b"RKA-v2-response".to_vec())
        })
    });

    let response = client.exchange(client_socket, b"RKA-v2-request")?;
    assert_eq!(response, b"RKA-v2-response");
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    match worker.join() {
        Ok(result) => result?,
        Err(_) => return Err("server thread failed".into()),
    }
    Ok(())
}

#[test]
fn reject_wrong_pin() -> Result<(), Box<dyn std::error::Error>> {
    let pki = test_pki()?;
    let trust = vec![pki.root.clone()];
    let client = PinnedTlsClient::new(
        pki.client.identity(),
        ClientPeer::new(
            trust.clone(),
            ServerName::try_from("localhost".to_owned())?,
            [0x55; 32],
        ),
        TlsAdmission::new(binding(), Duration::from_secs(2)),
    )?;
    let server = PinnedTlsServer::new(
        pki.server.identity(),
        &ServerPeer::new(trust, pki.client.pin),
        TlsAdmission::new(binding(), Duration::from_secs(2)),
    )?;
    let (client_socket, server_socket) = connected_pair()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let server_handled = Arc::clone(&handled);
    let worker = std::thread::spawn(move || {
        server.serve_once(server_socket, |request| {
            server_handled.fetch_add(1, Ordering::SeqCst);
            Ok(request.to_vec())
        })
    });

    assert_eq!(
        client.exchange(client_socket, b"must-not-write"),
        Err(TlsError::Pin)
    );
    assert_eq!(handled.load(Ordering::SeqCst), 0);
    let _server_result = worker.join();
    Ok(())
}

#[test]
fn deadline_and_redirect_restrictions_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    assert!(Endpoint::parse("https://localhost/path", 443).is_err());
    assert!(Endpoint::parse("LOCALHOST", 443).is_err());

    let pki = test_pki()?;
    let client = PinnedTlsClient::new(
        pki.client.identity(),
        ClientPeer::new(
            vec![pki.root],
            ServerName::try_from("localhost".to_owned())?,
            pki.server.pin,
        ),
        TlsAdmission::new(binding(), Duration::from_millis(20)),
    )?;
    let (client_socket, _stalled_peer) = connected_pair()?;
    assert_eq!(
        client.exchange(client_socket, b"must-not-write"),
        Err(TlsError::Deadline)
    );
    Ok(())
}

#[test]
fn transcript_mismatch_is_rejected_before_handler() -> Result<(), Box<dyn std::error::Error>> {
    let pki = test_pki()?;
    let trust = vec![pki.root.clone()];
    let client = PinnedTlsClient::new(
        pki.client.identity(),
        ClientPeer::new(
            trust.clone(),
            ServerName::try_from("localhost".to_owned())?,
            pki.server.pin,
        ),
        TlsAdmission::new(binding(), Duration::from_secs(2)),
    )?;
    let mut wrong_binding = binding();
    wrong_binding.transcript_hash = [0x44; 32];
    let server = PinnedTlsServer::new(
        pki.server.identity(),
        &ServerPeer::new(trust, pki.client.pin),
        TlsAdmission::new(wrong_binding, Duration::from_secs(2)),
    )?;
    let (client_socket, server_socket) = connected_pair()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let server_handled = Arc::clone(&handled);
    let worker = std::thread::spawn(move || {
        server.serve_once(server_socket, |request| {
            server_handled.fetch_add(1, Ordering::SeqCst);
            Ok(request.to_vec())
        })
    });

    assert_eq!(
        client.exchange(client_socket, b"must-not-write"),
        Err(TlsError::Admission)
    );
    assert_eq!(handled.load(Ordering::SeqCst), 0);
    let _server_result = worker.join();
    Ok(())
}

#[test]
fn replay_tombstone_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let key = request_tombstone(
        (PeerSpkiHash::new([7; 32]), 11, SessionId::new([8; 32])),
        (RequestId::new([9; 16]), MessageKind::Finish),
    );
    {
        let mut first = ReplayManager::load(&store)?;
        let permit = first.persist(&key, TombstoneTime::new(100, 11))?;
        assert_eq!(permit.key(), key);
    }
    let mut restarted = ReplayManager::load(&store)?;
    assert!(matches!(
        restarted.persist(&key, TombstoneTime::new(101, 11)),
        Err(StateError::Replay)
    ));
    Ok(())
}

#[test]
fn retained_session_id_is_skipped_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    {
        let mut manager = SessionManager::load(
            &store,
            SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
            (
                SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
                SessionLifecycle::new(),
            ),
        )?;
        let _session = manager.open_candidate(0)?;
    }
    let mut restarted = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![1; 32], vec![3; 32], vec![4; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    assert_eq!(restarted.open_candidate(1)?.id().bytes(), [3; 32]);
    Ok(())
}

#[test]
fn retained_request_id_rejects_cross_kind_after_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let store = MemoryStore::new();
    let retained = RequestId::new([9; 16]);
    {
        let mut manager = SessionManager::load(
            &store,
            SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
            (
                SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
                SessionLifecycle::new(),
            ),
        )?;
        let session = manager.open_candidate(0)?;
        let _permit = manager.admit_request_id(
            RequestContext::new(session.id(), MessageKind::Finish, 1),
            retained,
        )?;
    }
    let mut restarted = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![3; 32], vec![4; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let session = restarted.open_candidate(2)?;
    assert!(matches!(
        restarted.admit_request_id(
            RequestContext::new(session.id(), MessageKind::Abort, 3),
            retained,
        ),
        Err(SessionError::Replay)
    ));
    Ok(())
}

#[test]
fn generated_request_id_skips_retained_value_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    {
        let mut manager = SessionManager::load(
            &store,
            SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
            (
                SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
                SessionLifecycle::new(),
            ),
        )?;
        let session = manager.open_candidate(0)?;
        let _pending = manager.admit_request_id(
            RequestContext::new(session.id(), MessageKind::Finish, 1),
            RequestId::new([9; 16]),
        )?;
    }
    let mut restarted = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![3; 32], vec![4; 32], vec![9; 16], vec![10; 16]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let session = restarted.open_candidate(2)?;
    let pending =
        restarted.persist_request(RequestContext::new(session.id(), MessageKind::Abort, 3))?;
    assert_eq!(pending.coordinates().0.bytes(), [10; 16]);
    Ok(())
}

#[test]
fn repeated_retained_rng_values_exhaust_finite_budget() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    {
        let mut manager = SessionManager::load(
            &store,
            SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
            (
                SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
                SessionLifecycle::new(),
            ),
        )?;
        let _session = manager.open_candidate(0)?;
    }
    let repeated = (0..8).map(|_| vec![1; 32]).collect();
    let mut restarted = SessionManager::load(
        &store,
        SequenceRng::new(repeated),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    assert!(matches!(
        restarted.open_candidate(1),
        Err(SessionError::RandomExhausted)
    ));
    Ok(())
}

#[test]
fn duplicate_persisted_namespace_record_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    {
        let mut manager = SessionManager::load(
            &store,
            SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
            (
                SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
                SessionLifecycle::new(),
            ),
        )?;
        let _session = manager.open_candidate(0)?;
    }
    let key = b"rka-replay-v2".to_vec();
    let mut records = store.records.lock().map_err(|_| StateError::Storage)?;
    let original = records.get(&key).cloned().ok_or(StateError::Missing)?;
    let entry = original.get(1..).ok_or(StateError::Corrupt)?;
    let mut duplicate = Vec::with_capacity(entry.len().saturating_mul(2).saturating_add(1));
    duplicate.push(0x82);
    duplicate.extend_from_slice(entry);
    duplicate.extend_from_slice(entry);
    records.insert(key, duplicate);
    drop(records);
    assert!(matches!(
        ReplayManager::load(&store),
        Err(StateError::Corrupt)
    ));
    Ok(())
}

#[test]
fn pending_response_accepts_error_and_rejects_correlation_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let session = manager.open_candidate(0)?;
    let context = RequestContext::new(session.id(), MessageKind::Finish, 1);
    let wrong_id = manager.admit_request_id(context, RequestId::new([10; 16]))?;
    assert!(matches!(
        wrong_id.accept(ResponseContext::success(
            RequestId::new([99; 16]),
            MessageKind::Result,
            0,
        )),
        Err(SessionError::Correlation)
    ));
    let valid_error = manager.admit_request_id(context, RequestId::new([11; 16]))?;
    let _accepted = valid_error.accept(ResponseContext::protocol_error(
        RequestId::new([11; 16]),
        MessageKind::Finish,
        1,
    ))?;
    let wrong_error_trigger = manager.admit_request_id(context, RequestId::new([15; 16]))?;
    assert!(matches!(
        wrong_error_trigger.accept(ResponseContext::protocol_error(
            RequestId::new([15; 16]),
            MessageKind::Abort,
            2,
        )),
        Err(SessionError::Correlation)
    ));
    let wrong_kind = manager.admit_request_id(context, RequestId::new([14; 16]))?;
    assert!(matches!(
        wrong_kind.accept(ResponseContext::success(
            RequestId::new([14; 16]),
            MessageKind::HelloAck,
            3,
        )),
        Err(SessionError::Correlation)
    ));
    let wrong_sequence = manager.admit_request_id(context, RequestId::new([12; 16]))?;
    assert!(matches!(
        wrong_sequence.accept(ResponseContext::success(
            RequestId::new([12; 16]),
            MessageKind::Result,
            99,
        )),
        Err(SessionError::Correlation)
    ));
    let exact = manager.admit_request_id(context, RequestId::new([13; 16]))?;
    let _accepted = exact.accept(ResponseContext::success(
        RequestId::new([13; 16]),
        MessageKind::Result,
        5,
    ))?;
    Ok(())
}

#[test]
fn live_sessions_advance_sequences_independently() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![1; 32], vec![2; 32], vec![3; 32], vec![4; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let first = manager.open_candidate(0)?;
    let second = manager.open_candidate(0)?;
    let first_zero = manager.admit_request_id(
        RequestContext::new(first.id(), MessageKind::Finish, 1),
        RequestId::new([10; 16]),
    )?;
    let second_zero = manager.admit_request_id(
        RequestContext::new(second.id(), MessageKind::Finish, 1),
        RequestId::new([11; 16]),
    )?;
    let first_one = manager.admit_request_id(
        RequestContext::new(first.id(), MessageKind::Abort, 2),
        RequestId::new([12; 16]),
    )?;
    assert_eq!(first_zero.coordinates().1, 0);
    assert_eq!(second_zero.coordinates().1, 0);
    assert_eq!(first_one.coordinates().1, 1);
    Ok(())
}

#[test]
fn closed_session_sequence_state_is_destroyed() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![1; 32], vec![2; 32], vec![3; 32], vec![4; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let first = manager.open_candidate(0)?;
    let pending = manager.admit_request_id(
        RequestContext::new(first.id(), MessageKind::Finish, 1),
        RequestId::new([10; 16]),
    )?;
    assert_eq!(pending.coordinates().1, 0);
    first.close();
    let replacement = manager.open_candidate(2)?;
    let fresh = manager.admit_request_id(
        RequestContext::new(replacement.id(), MessageKind::Finish, 3),
        RequestId::new([11; 16]),
    )?;
    assert_eq!(fresh.coordinates().1, 0);
    Ok(())
}

#[test]
fn sequence_overflow_fails_before_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let lifecycle = SessionLifecycle::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            lifecycle.clone(),
        ),
    )?;
    let session = manager.open_candidate(0)?;
    lifecycle.set_next_sequence_for_test(session.id(), u32::MAX)?;
    let before = store
        .records
        .lock()
        .map_err(|_| StateError::Storage)?
        .clone();
    assert!(matches!(
        manager.admit_request_id(
            RequestContext::new(session.id(), MessageKind::Finish, 1),
            RequestId::new([10; 16]),
        ),
        Err(SessionError::Capacity)
    ));
    assert_eq!(
        *store.records.lock().map_err(|_| StateError::Storage)?,
        before
    );
    Ok(())
}

#[test]
fn slow_drip_frame_cannot_reset_absolute_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = connected_pair()?;
    let worker = std::thread::spawn(move || {
        for byte in [0_u8, 0, 0, 2, b'o', b'k'] {
            std::thread::sleep(Duration::from_millis(8));
            if writer.write_all(&[byte]).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    let result = read_frame(
        &mut RawTlsStream(reader),
        &Deadline::new(Duration::from_millis(20))?,
    );
    let elapsed = started.elapsed();
    assert_eq!(result, Err(TlsError::Deadline));
    assert!(elapsed < Duration::from_millis(60));
    if worker.join().is_err() {
        return Err("slow-drip worker failed".into());
    }
    Ok(())
}

#[test]
fn diagnostic_transport_never_satisfies_direct() {
    assert!(
        !super::TransportKind::DiagnosticUsbRelay.satisfies_direct(),
        "diagnostic relay must remain disjoint"
    );
}

#[test]
fn replay_retention_requires_time_and_epoch() -> Result<(), StateError> {
    for (age, epochs, removed) in [
        (86_399, 1, 0),
        (86_400, 1, 0),
        (86_399, 2, 0),
        (86_400, 2, 1),
    ] {
        let store = MemoryStore::new();
        let mut manager = ReplayManager::load(&store)?;
        manager.persist(
            &[1, u8::try_from(epochs).map_or(0, |value| value)],
            TombstoneTime::new(10, 5),
        )?;
        assert_eq!(
            manager.purge(TombstoneTime::new(10 + age, 5 + epochs))?,
            removed
        );
    }
    Ok(())
}

#[test]
fn persistence_failure_prevents_permit() -> Result<(), StateError> {
    let store = MemoryStore {
        records: Mutex::new(BTreeMap::new()),
        fail_replace: true,
    };
    let mut manager = ReplayManager::load(&store)?;
    assert!(matches!(
        manager.persist(&[1], TombstoneTime::new(1, 1)),
        Err(StateError::Storage)
    ));
    Ok(())
}

#[test]
fn session_persistence_failure_releases_unexposed_lease() -> Result<(), Box<dyn std::error::Error>>
{
    let lifecycle = SessionLifecycle::new();
    let failing = MemoryStore {
        records: Mutex::new(BTreeMap::new()),
        fail_replace: true,
    };
    let mut rejected = SessionManager::load(
        &failing,
        SequenceRng::new(vec![vec![1; 32], vec![2; 32]]),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            lifecycle.clone(),
        ),
    )?;
    assert!(matches!(
        rejected.open_candidate(0),
        Err(SessionError::State(StateError::Storage))
    ));
    let durable = MemoryStore::new();
    let mut admitted = SessionManager::load(
        &durable,
        SequenceRng::new(vec![vec![1; 32], vec![3; 32]]),
        (SessionScope::new(PeerSpkiHash::new([5; 32]), 9), lifecycle),
    )?;
    assert_eq!(admitted.open_candidate(1)?.id().bytes(), [1; 32]);
    Ok(())
}

#[derive(Debug)]
struct SequenceRng {
    values: Mutex<VecDeque<Vec<u8>>>,
}

impl SequenceRng {
    fn new(values: Vec<Vec<u8>>) -> Self {
        Self {
            values: Mutex::new(values.into()),
        }
    }
}

impl CsRng for SequenceRng {
    fn fill(&self, output: &mut [u8]) -> Result<(), SessionError> {
        let value = self
            .values
            .lock()
            .map_err(|_| SessionError::Random)?
            .pop_front()
            .ok_or(SessionError::Random)?;
        if value.len() != output.len() {
            return Err(SessionError::Random);
        }
        output.copy_from_slice(&value);
        Ok(())
    }
}

#[test]
fn session_bounds_and_correlation_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let mut random = Vec::new();
    for value in 1_u8..=8 {
        random.push(vec![value; 32]);
    }
    let store = MemoryStore::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(random),
        (
            SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
            SessionLifecycle::new(),
        ),
    )?;
    let first = manager.open_candidate(0)?;
    assert_ne!(first.id().bytes(), first.candidate_nonce());
    let mut leases = vec![first];
    for _ in 0..3 {
        leases.push(manager.open_candidate(0)?);
    }
    assert!(matches!(
        manager.open_candidate(0),
        Err(SessionError::Capacity)
    ));
    assert_eq!(leases.len(), 4);
    Ok(())
}

#[test]
fn profile_roles_hash_the_same_public_map() -> Result<(), Box<dyn std::error::Error>> {
    let pki = test_pki()?;
    let endpoint = Endpoint::parse("localhost", 443)?;
    let trust = vec![pki.root];
    let donor = PairedProfile::parse(ProfileInput {
        epoch: 3,
        local_role: Role::Donor,
        transport: TransportKind::DirectPinnedTls,
        endpoint: endpoint.clone(),
        local_spki: pki.server.pin,
        peer_spki: pki.client.pin,
        peer_trust: trust.clone(),
        allowed_identities: vec![[1; 32]],
        root_hash: [2; 32],
        policy_version: 1,
    })?;
    let candidate = PairedProfile::parse(ProfileInput {
        epoch: 3,
        local_role: Role::Candidate,
        transport: TransportKind::DirectPinnedTls,
        endpoint,
        local_spki: pki.client.pin,
        peer_spki: pki.server.pin,
        peer_trust: trust,
        allowed_identities: vec![[1; 32]],
        root_hash: [2; 32],
        policy_version: 1,
    })?;
    assert_eq!(donor.id(), candidate.id());
    assert!(candidate.transport().satisfies_direct());
    let lifecycle = SessionLifecycle::new();
    let mut rotation = ProfileRotation::new(candidate.clone(), lifecycle.clone());
    assert!(rotation.prepare(candidate).is_err());
    let store = MemoryStore::new();
    let mut manager = SessionManager::load(
        &store,
        SequenceRng::new(vec![vec![7; 32], vec![8; 32]]),
        (SessionScope::new(PeerSpkiHash::new([5; 32]), 3), lifecycle),
    )?;
    let live = manager.open_candidate(0)?;
    let rotated = test_pki()?;
    rotation.prepare(PairedProfile::parse(ProfileInput {
        epoch: 4,
        local_role: Role::Candidate,
        transport: TransportKind::DirectPinnedTls,
        endpoint: Endpoint::parse("localhost", 443)?,
        local_spki: rotated.client.pin,
        peer_spki: rotated.server.pin,
        peer_trust: vec![rotated.root],
        allowed_identities: vec![[1; 32]],
        root_hash: [2; 32],
        policy_version: 1,
    })?)?;
    assert_eq!(rotation.activate(), Err(ProfileError::SessionsLive));
    assert!(matches!(
        manager.open_candidate(1),
        Err(SessionError::Draining)
    ));
    live.close();
    rotation.activate()?;
    Ok(())
}

#[test]
fn audit_chain_signs_redacted_receipt_and_rejects_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let store = MemoryStore::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
    let private = Zeroizing::new(pkcs8.as_ref().to_vec());
    let mut chain = AuditChain::load(&store, &private)?;
    let entry = AuditEntry::new(
        (Stage::Transport, MessageKind::Finish),
        RkaErrorCode::InvalidRequest,
        [7; 32],
    );
    chain.append(entry)?;
    let raw_correlation = [0xa7; 32];
    let receipt = chain.receipt(ReceiptContext::new(
        8,
        TransportKind::DirectPinnedTls,
        raw_correlation,
    ));
    assert!(
        !receipt
            .encode()
            .windows(raw_correlation.len())
            .any(|window| window == raw_correlation)
    );
    let encoded = receipt.encode();
    let mut verifier = ReceiptVerifier::new(chain.public_key());
    verifier.verify_encoded(&encoded)?;
    assert!(matches!(
        verifier.verify_encoded(&encoded),
        Err(super::audit::AuditError::Replay)
    ));
    assert!(!format!("{receipt:?}").contains("070707"));
    let mut tampered = receipt.clone();
    tampered.flip_signature_bit();
    let mut fresh = ReceiptVerifier::new(chain.public_key());
    assert!(fresh.verify(&tampered).is_err());
    let mut wrong_key = ReceiptVerifier::new([0x42; 32]);
    assert!(wrong_key.verify_encoded(&encoded).is_err());
    let mut truncated = ReceiptVerifier::new(chain.public_key());
    assert!(
        truncated
            .verify_encoded(
                encoded
                    .get(..encoded.len().saturating_sub(1))
                    .ok_or("receipt")?
            )
            .is_err()
    );
    let mut extended_bytes = encoded.clone();
    extended_bytes.push(0);
    let mut extended = ReceiptVerifier::new(chain.public_key());
    assert!(extended.verify_encoded(&extended_bytes).is_err());
    let mut captured = encoded;
    for value in store
        .records
        .lock()
        .map_err(|_| StateError::Storage)?
        .values()
    {
        captured.extend_from_slice(value);
    }
    captured.extend_from_slice(format!("{chain:?}{receipt:?}").as_bytes());
    captured.extend_from_slice(super::audit::AuditError::Receipt.to_string().as_bytes());
    let forbidden = [raw_correlation.as_slice(), private.as_slice()];
    for canary in forbidden {
        assert!(
            !captured
                .windows(canary.len())
                .any(|window| window == canary)
        );
    }
    let restarted = AuditChain::load(&store, &private)?;
    let second = restarted.receipt(ReceiptContext::new(
        8,
        TransportKind::DirectPinnedTls,
        [10; 32],
    ));
    assert_ne!(receipt.encode(), second.encode());
    assert_eq!(
        Ed25519KeyPair::from_pkcs8(&private)?.public_key().as_ref(),
        chain.public_key()
    );
    Ok(())
}

#[test]
fn transport_debug_boundaries_redact_raw_identifiers() {
    let admission = TlsAdmission::new(binding(), Duration::from_secs(1));
    let request = RequestContext::new(SessionId::new([0xa9; 32]), MessageKind::Finish, 7);
    let captured = format!("{admission:?}{request:?}");
    assert!(!captured.contains("session_id"));
    assert!(!captured.contains("candidate_nonce"));
    assert!(!captured.contains("SessionId"));
}
