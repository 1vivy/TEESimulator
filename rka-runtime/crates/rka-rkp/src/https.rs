use std::{
    io::{self, Read},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use reqwest::{
    Method,
    blocking::{Client, Response},
    redirect::Policy,
};

use crate::{
    ClientError, HttpResponse, ResponseHeaders, StatusHttpTransport, StatusRequest,
    challenge::{HttpRequest, HttpTransport},
};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

/// Production bounded HTTPS transport with redirects and environment proxies disabled.
#[derive(Debug)]
pub struct BoundedHttpsTransport {
    client: Client,
}

impl BoundedHttpsTransport {
    /// Builds the production TLS client with native Android/Linux trust verification.
    pub fn new() -> Result<Self, ClientError> {
        let client = Client::builder()
            .tls_backend_rustls()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(NETWORK_TIMEOUT)
            .timeout(NETWORK_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self { client })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "closed HTTP exchange keeps method, URL, headers, and body explicit"
    )]
    fn exchange(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, ClientError> {
        if !url.starts_with("https://") {
            return Err(ClientError::Transport);
        }
        let posting = body.is_some();
        if posting {
            connect_before_upload(url)?;
        }
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(value) = body {
            request = request.body(value.to_vec());
        }
        let response = request.send().map_err(|_| after_handoff_failure(posting))?;
        bounded_response(response, posting)
    }
}

const fn after_handoff_failure(posting: bool) -> ClientError {
    if posting {
        ClientError::PostAmbiguous
    } else {
        ClientError::Transport
    }
}

fn connect_before_upload(url: &str) -> Result<(), ClientError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| ClientError::Transport)?;
    let host = parsed.host_str().ok_or(ClientError::Transport)?;
    let port = parsed
        .port_or_known_default()
        .ok_or(ClientError::Transport)?;
    let addresses = resolved_addresses((host, port).to_socket_addrs())?;
    let mut saw_refusal = false;
    for address in addresses.take(8) {
        match TcpStream::connect_timeout(&address, NETWORK_TIMEOUT) {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                saw_refusal = true;
            }
            Err(_) => return Err(ClientError::PostAmbiguous),
        }
    }
    if saw_refusal {
        Err(ClientError::ConnectBeforeUpload)
    } else {
        Err(ClientError::PostAmbiguous)
    }
}

fn resolved_addresses(
    result: io::Result<impl Iterator<Item = std::net::SocketAddr>>,
) -> Result<impl Iterator<Item = std::net::SocketAddr>, ClientError> {
    result.map_err(|_| ClientError::PostAmbiguous)
}

impl HttpTransport for BoundedHttpsTransport {
    fn post(&mut self, request: HttpRequest<'_>) -> Result<HttpResponse, ClientError> {
        self.exchange(
            Method::POST,
            request.url,
            request.headers,
            Some(request.body),
        )
    }
}

impl StatusHttpTransport for BoundedHttpsTransport {
    fn get(&mut self, request: StatusRequest<'_>) -> Result<HttpResponse, ClientError> {
        if request.url != crate::STATUS_URL {
            return Err(ClientError::Transport);
        }
        self.exchange(Method::GET, request.url, request.headers, None)
    }
}

fn bounded_response(response: Response, posting: bool) -> Result<HttpResponse, ClientError> {
    let maximum =
        u64::try_from(crate::MAX_PROVISIONING_BYTES).map_err(|_| ClientError::ResponseTooLarge)?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum)
    {
        return Err(ClientError::ResponseTooLarge);
    }
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|text| (name.as_str(), text))
                .map_err(|_| ClientError::Transport)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let headers =
        ResponseHeaders::collect_bounded(headers).map_err(|_| ClientError::ResponseTooLarge)?;
    let mut body = Vec::new();
    response
        .take(maximum.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| after_handoff_failure(posting))?;
    HttpResponse::new(status, headers, body)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn tls_handshake_failure_after_tcp_connect_is_never_retryable() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            drop(socket);
        });
        let mut transport = BoundedHttpsTransport::new().unwrap();
        let url = format!("https://{address}/");

        let result = transport.post(HttpRequest {
            url: &url,
            headers: &[],
            body: b"body",
        });

        server.join().unwrap();
        assert_eq!(result, Err(ClientError::PostAmbiguous));
    }

    #[test]
    fn exact_tcp_refusal_before_request_handoff_is_retryable() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut transport = BoundedHttpsTransport::new().unwrap();
        let url = format!("https://{address}/");

        let result = transport.post(HttpRequest {
            url: &url,
            headers: &[],
            body: b"body",
        });

        assert_eq!(result, Err(ClientError::ConnectBeforeUpload));
    }

    #[test]
    fn dns_and_post_handoff_failures_are_never_retryable() {
        let dns = resolved_addresses(Err::<std::vec::IntoIter<std::net::SocketAddr>, _>(
            io::Error::new(io::ErrorKind::NotFound, "injected DNS failure"),
        ));

        assert!(matches!(dns, Err(ClientError::PostAmbiguous)));
        assert_eq!(after_handoff_failure(true), ClientError::PostAmbiguous);
        assert_eq!(after_handoff_failure(false), ClientError::Transport);
    }
}
