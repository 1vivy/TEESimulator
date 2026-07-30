use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use rka_protocol::{MAX_FRAME_BYTES, sha256};
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, ServerName},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
    version::TLS13,
};
use webpki::anchor_from_trusted_cert;

use crate::tls_io::{Deadline, map_io, read_frame, set_timeout, write_frame};
use crate::{AdmissionBinding, ClientPeer, ServerPeer, TlsAdmission, TlsCredentials, TlsError};

/// TLS 1.3 candidate with standard `WebPKI` validation plus exact SPKI pinning.
#[derive(Debug)]
pub struct PinnedTlsClient {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    expected_pin: [u8; 32],
    binding: AdmissionBinding,
    budget: Duration,
}

impl PinnedTlsClient {
    /// Builds a TLS1.3-only client with mTLS, no early data, and no resumption.
    pub fn new(
        credentials: TlsCredentials,
        peer: ClientPeer,
        admission: TlsAdmission,
    ) -> Result<Self, TlsError> {
        let roots = roots(&peer.trust)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(credentials.chain, credentials.key)
            .map_err(|_| TlsError::Configuration)?;
        config.enable_early_data = false;
        config.resumption = Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
            name: peer.name,
            expected_pin: peer.pin,
            binding: admission.binding,
            budget: admission.budget,
        })
    }

    /// Completes admission before writing any caller request bytes.
    pub fn exchange(&self, socket: TcpStream, request: &[u8]) -> Result<Vec<u8>, TlsError> {
        if request.is_empty() || request.len() > MAX_FRAME_BYTES {
            return Err(TlsError::Frame);
        }
        let deadline = Deadline::new(self.budget)?;
        let connection = ClientConnection::new(Arc::clone(&self.config), self.name.clone())
            .map_err(|_| TlsError::Configuration)?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_client_handshake(&mut stream, &deadline)?;
        verify_common(
            stream.conn.protocol_version(),
            stream.conn.peer_certificates(),
            self.expected_pin,
        )?;
        let mut token = [0_u8; 32];
        set_timeout(&stream.sock, &deadline)?;
        stream
            .read_exact(&mut token)
            .map_err(|error| map_io(&error))?;
        if token != self.binding.token() {
            return Err(TlsError::Admission);
        }
        write_frame(&mut stream, request, &deadline)?;
        read_frame(&mut stream, &deadline)
    }
}

/// TLS 1.3 donor that admits an exact pinned client before dispatch.
#[derive(Debug)]
pub struct PinnedTlsServer {
    config: Arc<ServerConfig>,
    expected_pin: [u8; 32],
    binding: AdmissionBinding,
    budget: Duration,
}

impl PinnedTlsServer {
    /// Builds a TLS1.3-only server requiring a WebPKI-valid client certificate.
    pub fn new(
        credentials: TlsCredentials,
        peer: &ServerPeer,
        admission: TlsAdmission,
    ) -> Result<Self, TlsError> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots(&peer.trust)?))
            .build()
            .map_err(|_| TlsError::Configuration)?;
        let mut config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(credentials.chain, credentials.key)
            .map_err(|_| TlsError::Configuration)?;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Self {
            config: Arc::new(config),
            expected_pin: peer.pin,
            binding: admission.binding,
            budget: admission.budget,
        })
    }

    /// Dispatches exactly once after mTLS, pin, and admission token ordering.
    pub fn serve_once<F>(&self, socket: TcpStream, handler: F) -> Result<(), TlsError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, TlsError>,
    {
        let deadline = Deadline::new(self.budget)?;
        let connection =
            ServerConnection::new(Arc::clone(&self.config)).map_err(|_| TlsError::Configuration)?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_server_handshake(&mut stream, &deadline)?;
        verify_common(
            stream.conn.protocol_version(),
            stream.conn.peer_certificates(),
            self.expected_pin,
        )?;
        set_timeout(&stream.sock, &deadline)?;
        stream
            .write_all(&self.binding.token())
            .and_then(|()| stream.flush())
            .map_err(|error| map_io(&error))?;
        let request = read_frame(&mut stream, &deadline)?;
        let response = handler(&request)?;
        write_frame(&mut stream, &response, &deadline)
    }
}

/// Parses a certificate with rustls-webpki and hashes its exact SPKI DER.
pub fn peer_spki_hash(certificate: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
    let anchor = anchor_from_trusted_cert(certificate).map_err(|_| TlsError::Certificate)?;
    let value = anchor.subject_public_key_info.as_ref();
    let mut spki = Vec::with_capacity(value.len().saturating_add(4));
    spki.push(0x30);
    encode_der_length(&mut spki, value.len())?;
    spki.extend_from_slice(value);
    Ok(sha256(&spki))
}

fn encode_der_length(output: &mut Vec<u8>, length: usize) -> Result<(), TlsError> {
    match length {
        0..=127 => output.push(u8::try_from(length).map_err(|_| TlsError::Certificate)?),
        128..=255 => {
            output.push(0x81);
            output.push(u8::try_from(length).map_err(|_| TlsError::Certificate)?);
        }
        256..=65_535 => {
            output.push(0x82);
            output.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| TlsError::Certificate)?
                    .to_be_bytes(),
            );
        }
        _ => return Err(TlsError::Certificate),
    }
    Ok(())
}

fn roots(certificates: &[CertificateDer<'static>]) -> Result<RootCertStore, TlsError> {
    if certificates.is_empty() {
        return Err(TlsError::Configuration);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.clone())
            .map_err(|_| TlsError::Certificate)?;
    }
    Ok(roots)
}

fn verify_common(
    version: Option<ProtocolVersion>,
    certificates: Option<&[CertificateDer<'static>]>,
    expected: [u8; 32],
) -> Result<(), TlsError> {
    if version != Some(ProtocolVersion::TLSv1_3) {
        return Err(TlsError::Version);
    }
    let leaf = certificates
        .and_then(|chain| chain.first())
        .ok_or(TlsError::Certificate)?;
    let actual = peer_spki_hash(leaf)?;
    if actual == expected {
        Ok(())
    } else {
        Err(TlsError::Pin)
    }
}

fn complete_client_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.is_handshaking() {
        set_timeout(&stream.sock, deadline)?;
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| map_io(&error))?;
    }
    Ok(())
}

fn complete_server_handshake(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.is_handshaking() {
        set_timeout(&stream.sock, deadline)?;
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| map_io(&error))?;
    }
    Ok(())
}
