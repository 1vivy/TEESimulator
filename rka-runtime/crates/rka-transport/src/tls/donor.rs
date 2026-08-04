use std::{net::TcpStream, sync::Arc, time::Duration};

use rustls::{
    ClientConfig, ClientConnection, StreamOwned, client::Resumption, pki_types::ServerName,
    version::TLS13,
};

use super::{roots, verify_common};
use crate::{
    AdmissionBinding, ClientPeer, TlsAdmission, TlsCredentials, TlsError,
    tls_handshake::complete_client_handshake,
    tls_io::{Deadline, flush_bytes, read_frame, write_bytes, write_frame},
};

/// TLS 1.3 donor dialer carrying opaque authenticated dispatch context.
#[derive(Debug)]
pub struct PinnedTlsDonorClient<T> {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    expected_pin: [u8; 32],
    binding: AdmissionBinding,
    budget: Duration,
    authenticated: T,
}

impl<T> PinnedTlsDonorClient<T> {
    /// Builds a donor dialer with mutual authentication and exact candidate pinning.
    #[allow(
        clippy::too_many_arguments,
        reason = "authenticated payload is an opaque fourth input required by the transport seam"
    )]
    pub fn new(
        credentials: TlsCredentials,
        peer: ClientPeer,
        admission: TlsAdmission,
        authenticated: T,
    ) -> Result<Self, TlsError> {
        let roots = roots(&peer.trust)?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&TLS13])
                .map_err(|_| TlsError::Configuration)?
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
            authenticated,
        })
    }

    /// Reads and dispatches one candidate-originated request on a donor-opened socket.
    pub fn serve_once<F>(&self, socket: TcpStream, handler: F) -> Result<(), TlsError>
    where
        F: FnOnce(&T, &[u8]) -> Result<Vec<u8>, TlsError>,
    {
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
        write_bytes(&mut stream, &self.binding.token(), &deadline)?;
        flush_bytes(&mut stream, &deadline)?;
        let request = read_frame(&mut stream, &deadline)?;
        let response = handler(&self.authenticated, &request)?;
        write_frame(&mut stream, &response, &deadline)
    }
}
