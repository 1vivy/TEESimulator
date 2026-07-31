use std::{io::Read, time::Duration};

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
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(value) = body {
            request = request.body(value.to_vec());
        }
        bounded_response(request.send().map_err(|_| ClientError::Transport)?)
    }
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

fn bounded_response(response: Response) -> Result<HttpResponse, ClientError> {
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
        .map_err(|_| ClientError::Transport)?;
    HttpResponse::new(status, headers, body)
}
