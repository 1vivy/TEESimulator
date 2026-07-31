use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair as RcgenKeyPair, KeyUsagePurpose, PublicKeyData, date_time_ymd,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
    version::TLS13,
};

use super::{
    AdmissionBinding, ClientPeer, PinnedTlsClient, PinnedTlsServer, ServerPeer, TlsAdmission,
    TlsCredentials, TlsError,
    tls_handshake::{complete_client_handshake, complete_server_handshake},
    tls_io::{Deadline, flush_bytes, read_exact, read_frame, write_bytes, write_frame},
};

const BUDGET: Duration = Duration::from_millis(35);
const TOLERANCE: Duration = Duration::from_millis(180);
const PEER_BUDGET: Duration = Duration::from_secs(2);

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

#[derive(Clone, Copy)]
enum Validity {
    Current,
    Expired,
    Future,
}

fn test_pki(server_validity: Validity) -> Result<TestPki, Box<dyn std::error::Error>> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca_key = RcgenKeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    Ok(TestPki {
        root: ca.der().clone(),
        server: leaf(&issuer, true, server_validity)?,
        client: leaf(&issuer, false, Validity::Current)?,
    })
}

fn leaf(
    issuer: &Issuer<'_, RcgenKeyPair>,
    server: bool,
    validity: Validity,
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
    match validity {
        Validity::Current => {}
        Validity::Expired => {
            params.not_before = date_time_ymd(2019, 1, 1);
            params.not_after = date_time_ymd(2020, 1, 1);
        }
        Validity::Future => {
            params.not_before = date_time_ymd(2040, 1, 1);
            params.not_after = date_time_ymd(2041, 1, 1);
        }
    }
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

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.clone())
        .map_err(|_| TlsError::Certificate)?;
    Ok(roots)
}

fn custom_server(pki: &TestPki) -> Result<ServerConnection, TlsError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots(&pki.root)?))
        .build()
        .map_err(|_| TlsError::Configuration)?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            pki.server.chain.clone(),
            PrivatePkcs8KeyDer::from(pki.server.key.clone()).into(),
        )
        .map_err(|_| TlsError::Configuration)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    ServerConnection::new(Arc::new(config)).map_err(|_| TlsError::Configuration)
}

fn custom_client(pki: &TestPki) -> Result<ClientConnection, TlsError> {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots(&pki.root)?)
        .with_client_auth_cert(
            pki.client.chain.clone(),
            PrivatePkcs8KeyDer::from(pki.client.key.clone()).into(),
        )
        .map_err(|_| TlsError::Configuration)?;
    config.enable_early_data = false;
    config.resumption = Resumption::disabled();
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost".to_owned()).map_err(|_| TlsError::Configuration)?,
    )
    .map_err(|_| TlsError::Configuration)
}

fn production_client(
    pki: &TestPki,
    peer: (&str, [u8; 32], Duration),
) -> Result<PinnedTlsClient, Box<dyn std::error::Error>> {
    let (name, pin, budget) = peer;
    Ok(PinnedTlsClient::new(
        pki.client.identity(),
        ClientPeer::new(
            vec![pki.root.clone()],
            ServerName::try_from(name.to_owned())?,
            pin,
        ),
        TlsAdmission::new(binding(), budget),
    )?)
}

fn production_server(
    pki: &TestPki,
    pin: [u8; 32],
    budget: Duration,
) -> Result<PinnedTlsServer, TlsError> {
    PinnedTlsServer::new(
        pki.server.identity(),
        &ServerPeer::new(vec![pki.root.clone()], pin),
        TlsAdmission::new(binding(), budget),
    )
}

fn server_record(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    plaintext: &[u8],
    drip: bool,
) -> Result<(), TlsError> {
    stream
        .conn
        .writer()
        .write_all(plaintext)
        .map_err(|_| TlsError::Io)?;
    let mut ciphertext = Vec::new();
    while stream.conn.wants_write() {
        stream
            .conn
            .write_tls(&mut ciphertext)
            .map_err(|_| TlsError::Io)?;
    }
    for chunk in ciphertext.chunks(if drip { 1 } else { ciphertext.len().max(1) }) {
        if stream.sock.write_all(chunk).is_err() {
            break;
        }
        if drip {
            std::thread::sleep(Duration::from_millis(9));
        }
    }
    Ok(())
}

fn client_record(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    plaintext: &[u8],
    drip: bool,
) -> Result<(), TlsError> {
    stream
        .conn
        .writer()
        .write_all(plaintext)
        .map_err(|_| TlsError::Io)?;
    let mut ciphertext = Vec::new();
    while stream.conn.wants_write() {
        stream
            .conn
            .write_tls(&mut ciphertext)
            .map_err(|_| TlsError::Io)?;
    }
    for chunk in ciphertext.chunks(if drip { 1 } else { ciphertext.len().max(1) }) {
        if stream.sock.write_all(chunk).is_err() {
            break;
        }
        if drip {
            std::thread::sleep(Duration::from_millis(9));
        }
    }
    Ok(())
}

fn join(worker: JoinHandle<Result<(), TlsError>>) -> Result<(), Box<dyn std::error::Error>> {
    match worker.join() {
        Ok(Ok(()) | Err(TlsError::Io | TlsError::Deadline)) => Ok(()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(_) => Err("TLS peer thread failed".into()),
    }
}

fn assert_deadline(result: &Result<Vec<u8>, TlsError>, started: Instant) {
    assert_eq!(*result, Err(TlsError::Deadline));
    assert!(started.elapsed() >= BUDGET);
    assert!(started.elapsed() < TOLERANCE);
}

fn handshake_drip(pki: &TestPki) -> Result<(), Box<dyn std::error::Error>> {
    let client = production_client(pki, ("localhost", pki.server.pin, BUDGET))?;
    let connection = custom_server(pki)?;
    let (client_socket, mut server_socket) = connected_pair()?;
    let worker = std::thread::spawn(move || {
        let mut connection = connection;
        server_socket
            .set_read_timeout(Some(PEER_BUDGET))
            .map_err(|_| TlsError::Io)?;
        while !connection.wants_write() {
            if connection
                .read_tls(&mut server_socket)
                .map_err(|_| TlsError::Io)?
                == 0
            {
                return Err(TlsError::Io);
            }
            connection.process_new_packets().map_err(|_| TlsError::Io)?;
        }
        let mut ciphertext = Vec::new();
        connection
            .write_tls(&mut ciphertext)
            .map_err(|_| TlsError::Io)?;
        for byte in ciphertext {
            if server_socket.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(9));
        }
        Ok(())
    });
    let started = Instant::now();
    assert_deadline(&client.exchange(client_socket, b"request"), started);
    join(worker)
}

fn client_read_drip(pki: &TestPki, phase: u8) -> Result<(), Box<dyn std::error::Error>> {
    let client = production_client(pki, ("localhost", pki.server.pin, BUDGET))?;
    let connection = custom_server(pki)?;
    let (client_socket, server_socket) = connected_pair()?;
    let worker = std::thread::spawn(move || {
        let mut stream = StreamOwned::new(connection, server_socket);
        let deadline = Deadline::new(PEER_BUDGET)?;
        complete_server_handshake(&mut stream, &deadline)?;
        if phase == 0 {
            return server_record(&mut stream, &binding().token(), true);
        }
        write_bytes(&mut stream, &binding().token(), &deadline)?;
        flush_bytes(&mut stream, &deadline)?;
        let _request = read_frame(&mut stream, &deadline)?;
        if phase == 1 {
            server_record(&mut stream, &2_u32.to_be_bytes(), true)
        } else {
            server_record(&mut stream, &2_u32.to_be_bytes(), false)?;
            server_record(&mut stream, b"ok", true)
        }
    });
    let started = Instant::now();
    assert_deadline(&client.exchange(client_socket, b"request"), started);
    join(worker)
}

fn server_read_drip(pki: &TestPki, phase: u8) -> Result<(), Box<dyn std::error::Error>> {
    let server = production_server(pki, pki.client.pin, BUDGET)?;
    let connection = custom_client(pki)?;
    let (client_socket, server_socket) = connected_pair()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&handled);
    let worker = std::thread::spawn(move || {
        let started = Instant::now();
        let result = server.serve_once(server_socket, |request| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(request.to_vec())
        });
        assert_eq!(result, Err(TlsError::Deadline));
        assert!(started.elapsed() >= BUDGET);
        assert!(started.elapsed() < TOLERANCE);
        Ok(())
    });
    let mut stream = StreamOwned::new(connection, client_socket);
    let deadline = Deadline::new(PEER_BUDGET)?;
    complete_client_handshake(&mut stream, &deadline)?;
    if phase == 0 {
        client_record(&mut stream, &2_u32.to_be_bytes(), true)?;
    } else {
        client_record(&mut stream, &2_u32.to_be_bytes(), false)?;
        client_record(&mut stream, b"ok", true)?;
    }
    let mut token = [0; 32];
    read_exact(&mut stream, &mut token, &deadline)?;
    assert_eq!(token, binding().token());
    join(worker)?;
    assert_eq!(handled.load(Ordering::SeqCst), 0);
    Ok(())
}

fn response_backpressure(pki: &TestPki) -> Result<(), Box<dyn std::error::Error>> {
    let server = production_server(pki, pki.client.pin, Duration::from_millis(120))?;
    let connection = custom_client(pki)?;
    let (client_socket, server_socket) = connected_pair()?;
    let mut saturated = server_socket.try_clone()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&handled);
    let filler_worker = Arc::new(Mutex::new(None));
    let server_filler = Arc::clone(&filler_worker);
    let worker = std::thread::spawn(move || {
        let result = server.serve_once(server_socket, move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            saturated.set_nonblocking(true).map_err(|_| TlsError::Io)?;
            let filler = vec![0_u8; 65_536].into_boxed_slice();
            loop {
                match saturated.write(&filler) {
                    Ok(0) => return Err(TlsError::Io),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err(TlsError::Io),
                }
            }
            saturated.set_nonblocking(false).map_err(|_| TlsError::Io)?;
            let filler_thread =
                std::thread::spawn(move || while saturated.write_all(&filler).is_ok() {});
            *server_filler.lock().map_err(|_| TlsError::Io)? = Some(filler_thread);
            Ok(vec![0x5a; rka_protocol::MAX_FRAME_BYTES])
        });
        let filler = filler_worker.lock().map_err(|_| TlsError::Io)?.take();
        if filler.is_some_and(|thread| thread.join().is_err()) {
            return Err(TlsError::Io);
        }
        result
    });
    let mut stream = StreamOwned::new(connection, client_socket);
    let deadline = Deadline::new(PEER_BUDGET)?;
    complete_client_handshake(&mut stream, &deadline)?;
    let mut token = [0; 32];
    read_exact(&mut stream, &mut token, &deadline)?;
    write_frame(&mut stream, b"request", &deadline)?;
    std::thread::sleep(Duration::from_millis(250));
    match worker.join() {
        Ok(Err(TlsError::Deadline)) => {}
        Ok(result) => return Err(format!("response backpressure result: {result:?}").into()),
        Err(_) => return Err("response backpressure thread failed".into()),
    }
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn aggregate_tls_deadline_boundaries_are_independently_driven()
-> Result<(), Box<dyn std::error::Error>> {
    let before = std::fs::read_dir("/proc/self/fd")?.count();
    let pki = test_pki(Validity::Current)?;
    handshake_drip(&pki)?;
    client_read_drip(&pki, 0)?;
    client_read_drip(&pki, 1)?;
    client_read_drip(&pki, 2)?;
    server_read_drip(&pki, 0)?;
    server_read_drip(&pki, 1)?;
    response_backpressure(&pki)?;
    let after = std::fs::read_dir("/proc/self/fd")?.count();
    assert!(after <= before.saturating_add(2));
    Ok(())
}

type MutationResult = (Result<Vec<u8>, TlsError>, Result<(), TlsError>, usize);

fn mutation_pair(
    pki: &TestPki,
    peer: (&str, [u8; 32], [u8; 32]),
) -> Result<MutationResult, Box<dyn std::error::Error>> {
    let (client_name, server_pin, client_pin) = peer;
    let client = production_client(pki, (client_name, server_pin, PEER_BUDGET))?;
    let server = production_server(pki, client_pin, PEER_BUDGET)?;
    let (client_socket, server_socket) = connected_pair()?;
    let handled = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&handled);
    let worker = std::thread::spawn(move || {
        server.serve_once(server_socket, |request| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(request.to_vec())
        })
    });
    let client_result = client.exchange(client_socket, b"must-not-dispatch");
    let server_result = worker.join().map_err(|_| "TLS mutation thread failed")?;
    Ok((client_result, server_result, handled.load(Ordering::SeqCst)))
}

#[test]
fn webpki_mutations_reject_before_reciprocal_admission() -> Result<(), Box<dyn std::error::Error>> {
    let current = test_pki(Validity::Current)?;
    let client_pin = current.client.pin;
    let (client, _server, handled) =
        mutation_pair(&current, ("localhost", [0x51; 32], client_pin))?;
    assert_eq!(client, Err(TlsError::Pin));
    assert_eq!(handled, 0);

    let current = test_pki(Validity::Current)?;
    let server_pin = current.server.pin;
    let (client, server, handled) = mutation_pair(&current, ("localhost", server_pin, [0x52; 32]))?;
    assert!(client.is_err());
    assert_eq!(server, Err(TlsError::Pin));
    assert_eq!(handled, 0);

    let current = test_pki(Validity::Current)?;
    let server_pin = current.server.pin;
    let client_pin = current.client.pin;
    let (client, _server, handled) =
        mutation_pair(&current, ("wrong.invalid", server_pin, client_pin))?;
    assert!(client.is_err());
    assert_eq!(handled, 0);

    for validity in [Validity::Expired, Validity::Future] {
        let invalid = test_pki(validity)?;
        let server_pin = invalid.server.pin;
        let client_pin = invalid.client.pin;
        let (client, _server, handled) =
            mutation_pair(&invalid, ("localhost", server_pin, client_pin))?;
        assert!(client.is_err());
        assert_eq!(handled, 0);
    }

    let malformed = CertificateDer::from(vec![0x30, 1, 0]);
    assert!(
        PinnedTlsClient::new(
            test_pki(Validity::Current)?.client.identity(),
            ClientPeer::new(
                vec![malformed],
                ServerName::try_from("localhost".to_owned())?,
                [0; 32],
            ),
            TlsAdmission::new(binding(), PEER_BUDGET),
        )
        .is_err()
    );

    let downgrade = test_pki(Validity::Current)?;
    let client = production_client(&downgrade, ("localhost", downgrade.server.pin, BUDGET))?;
    let (client_socket, mut server_socket) = connected_pair()?;
    let worker = std::thread::spawn(move || {
        let mut client_hello = [0_u8; 4096];
        server_socket
            .set_read_timeout(Some(PEER_BUDGET))
            .map_err(|_| TlsError::Io)?;
        let _length = server_socket
            .read(&mut client_hello)
            .map_err(|_| TlsError::Io)?;
        let mut hello = vec![0x16, 0x03, 0x03, 0, 44, 0x02, 0, 0, 40, 0x03, 0x03];
        hello.extend_from_slice(&[0x33; 32]);
        hello.extend_from_slice(&[0, 0xc0, 0x2f, 0, 0, 0]);
        server_socket.write_all(&hello).map_err(|_| TlsError::Io)
    });
    assert!(
        client
            .exchange(client_socket, b"must-not-dispatch")
            .is_err()
    );
    match worker.join() {
        Ok(Ok(()) | Err(_)) => {}
        Err(_) => return Err("TLS downgrade thread failed".into()),
    }
    Ok(())
}
