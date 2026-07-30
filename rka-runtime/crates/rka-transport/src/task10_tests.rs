use std::{
    collections::{BTreeMap, VecDeque},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
    PinnedTlsClient, PinnedTlsServer, ProfileInput, ProfileRotation, ReceiptContext,
    ReceiptVerifier, Role, ServerPeer, SessionError, SessionManager, SessionScope, TlsAdmission,
    TlsCredentials, TlsError, TransportKind, peer_spki_hash,
};
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
        SessionScope::new(PeerSpkiHash::new([5; 32]), 9),
    )?;
    let first = manager.open_candidate(0)?;
    assert_ne!(first.id().bytes(), first.candidate_nonce());
    for _ in 0..3 {
        let _session = manager.open_candidate(0)?;
    }
    assert_eq!(manager.open_candidate(0), Err(SessionError::Capacity));
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
    let mut rotation = ProfileRotation::new(candidate.clone());
    assert!(rotation.prepare(candidate).is_err());
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
    chain.append(AuditEntry::new(
        (Stage::Transport, MessageKind::Finish),
        RkaErrorCode::InvalidRequest,
        [7; 32],
    ))?;
    let receipt = chain.receipt(ReceiptContext::new(
        8,
        TransportKind::DirectPinnedTls,
        [9; 32],
    ));
    let mut verifier = ReceiptVerifier::new(chain.public_key());
    verifier.verify(&receipt)?;
    assert!(matches!(
        verifier.verify(&receipt),
        Err(super::audit::AuditError::Replay)
    ));
    assert!(!format!("{receipt:?}").contains("070707"));
    let mut tampered = receipt.clone();
    tampered.flip_signature_bit();
    let mut fresh = ReceiptVerifier::new(chain.public_key());
    assert!(fresh.verify(&tampered).is_err());
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
