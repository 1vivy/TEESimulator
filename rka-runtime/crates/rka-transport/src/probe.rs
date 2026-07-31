use std::{net::SocketAddr, net::TcpStream, sync::Arc, time::Duration};

use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error,
    SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};

use crate::{TlsError, peer_spki_hash, tls_handshake::complete_client_handshake, tls_io::Deadline};

#[derive(Debug)]
struct ExactPinVerifier {
    expected: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ExactPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual = peer_spki_hash(end_entity)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if actual != self.expected {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Completes one TLS-1.3 handshake whose leaf SPKI matches the expected pin.
pub fn probe_pinned_tls(
    address: SocketAddr,
    expected_pin: [u8; 32],
    budget: Duration,
) -> Result<(), TlsError> {
    let provider = ring::default_provider();
    let verifier = ExactPinVerifier {
        expected: expected_pin,
        algorithms: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| TlsError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let socket = TcpStream::connect_timeout(&address, budget).map_err(|_| TlsError::Io)?;
    let name = ServerName::IpAddress(address.ip().into());
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| TlsError::Configuration)?;
    let mut stream = StreamOwned::new(connection, socket);
    let deadline = Deadline::new(budget)?;
    complete_client_handshake(&mut stream, &deadline)
}

#[cfg(test)]
mod tests {
    use std::{
        net::TcpListener,
        sync::Arc,
        thread::{self, JoinHandle},
        time::Duration,
    };

    use rcgen::generate_simple_self_signed;
    use rustls::{
        ServerConfig, ServerConnection, StreamOwned, crypto::ring, pki_types::PrivatePkcs8KeyDer,
        version::TLS13,
    };

    use super::probe_pinned_tls;
    use crate::peer_spki_hash;

    type TestServer = (std::net::SocketAddr, [u8; 32], JoinHandle<()>);

    fn server() -> Result<TestServer, Box<dyn std::error::Error>> {
        let identity = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
        let pin = peer_spki_hash(identity.cert.der())?;
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let Ok(connection) = ServerConnection::new(Arc::new(config)) else {
                return;
            };
            let mut stream = StreamOwned::new(connection, socket);
            while stream.conn.is_handshaking() {
                if stream.conn.complete_io(&mut stream.sock).is_err() {
                    return;
                }
            }
        });
        Ok((address, pin, handle))
    }

    #[test]
    fn exact_pin_completes_tls13_handshake() -> Result<(), Box<dyn std::error::Error>> {
        let (address, pin, server) = server()?;
        probe_pinned_tls(address, pin, Duration::from_secs(2))?;
        server.join().map_err(|_| "server thread failed")?;
        Ok(())
    }

    #[test]
    fn wrong_pin_rejects_peer() -> Result<(), Box<dyn std::error::Error>> {
        let (address, mut pin, server) = server()?;
        pin[0] ^= 0xff;
        assert!(probe_pinned_tls(address, pin, Duration::from_secs(2)).is_err());
        server.join().map_err(|_| "server thread failed")?;
        Ok(())
    }
}
