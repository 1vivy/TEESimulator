//! Closed HTTP request construction and challenge/configuration state machine.

use std::fs::File;
use std::io::Read;

use thiserror::Error;

use crate::config::{BaseUrl, ConfigError, ProvisioningInfo, parse_fetch_response};
use crate::outcome::{FailureDisposition, PostFailure, UploadProgress};
use crate::{MAX_PROVISIONING_BYTES, ResponseHeaders, base64_url, uuid};

const MAX_CHALLENGE_BYTES: usize = 64;

/// A closed POST request. The transport must not follow redirects.
#[derive(Debug)]
#[non_exhaustive]
pub struct HttpRequest<'a> {
    /// Exact HTTPS URL.
    pub url: &'a str,
    /// Exact request headers.
    pub headers: &'a [(&'a str, &'a str)],
    /// Bounded request body.
    pub body: &'a [u8],
}

/// Owned response returned without redirect processing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HttpResponse {
    status: u16,
    headers: ResponseHeaders,
    body: Vec<u8>,
}

impl HttpResponse {
    /// Constructs a response only from already bounded headers and a bounded body.
    pub fn new(status: u16, headers: ResponseHeaders, body: Vec<u8>) -> Result<Self, ClientError> {
        if body.len() > MAX_PROVISIONING_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// Returns the response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the bounded response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the bounded canonical response headers.
    pub const fn headers(&self) -> &ResponseHeaders {
        &self.headers
    }

    #[cfg(test)]
    fn ok(body: Vec<u8>) -> Self {
        Self::new(
            200,
            ResponseHeaders::collect_bounded(std::iter::empty::<(&str, &str)>()).unwrap(),
            body,
        )
        .unwrap()
    }
}

/// Closed transport abstraction with redirect handling disabled.
pub trait HttpTransport {
    /// Sends one POST.
    fn post(&mut self, request: HttpRequest<'_>) -> Result<HttpResponse, ClientError>;
}

/// Root-owned storage for the effective provisioning base.
pub trait EffectiveBaseStore {
    /// Loads a previously accepted override.
    fn load(&self) -> Option<BaseUrl>;
    /// Durably stores an accepted override.
    fn store(&mut self, base: &BaseUrl) -> Result<(), ClientError>;
}

/// Entropy used to create a fresh request identifier.
pub trait EntropySource {
    /// Fills exactly 128 random bits.
    fn fill_uuid(&mut self, output: &mut [u8; 16]) -> Result<(), ClientError>;
}

/// Durable uniqueness journal written before every upload.
pub trait AttemptJournal {
    /// Returns false when the identifier was already recorded.
    fn record(&mut self, request_id: &str) -> Result<bool, ClientError>;
}

/// Production entropy sourced directly from the kernel.
#[derive(Debug)]
#[non_exhaustive]
pub struct OsEntropy;

impl OsEntropy {
    /// Creates the production kernel entropy source.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for OsEntropy {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for OsEntropy {
    fn fill_uuid(&mut self, output: &mut [u8; 16]) -> Result<(), ClientError> {
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(output))
            .map_err(|_| ClientError::Entropy)
    }
}

/// Parsed bounded challenge and effective base for a provisioning batch.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FetchConfiguration {
    /// Server freshness challenge.
    pub challenge: Vec<u8>,
    /// Effective base after applying a valid override.
    pub effective_base: BaseUrl,
}

/// Successful sign response bound to its durable request identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCertificateResponse {
    request_id: String,
    response: HttpResponse,
}

impl SignedCertificateResponse {
    /// Returns the durable local request identifier bound to this upload.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the bounded provisioning response.
    pub const fn response(&self) -> &HttpResponse {
        &self.response
    }
}

/// Redacted provisioning client failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ClientError {
    /// The configured base was not canonical HTTPS.
    #[error("invalid provisioning base URL")]
    InvalidBaseUrl,
    /// The Task-18 body crossed the fixed boundary.
    #[error("provisioning request is too large")]
    RequestTooLarge,
    /// A response crossed the fixed boundary.
    #[error("provisioning response is too large")]
    ResponseTooLarge,
    /// A challenge was outside 16..=64 bytes.
    #[error("invalid provisioning challenge")]
    ChallengeSize,
    /// A response did not have the exact bounded CBOR shape.
    #[error("invalid provisioning response")]
    InvalidResponse,
    /// A redirect or Location header was returned.
    #[error("provisioning redirect rejected")]
    Redirect,
    /// The response status was not successful.
    #[error("provisioning server returned failure")]
    HttpStatus,
    /// The closed transport failed.
    #[error("provisioning transport failed")]
    Transport,
    /// Connection establishment failed before any request byte was written.
    #[error("provisioning connection failed before upload")]
    ConnectBeforeUpload,
    /// The request may have reached the server without a durable response.
    #[error("provisioning POST outcome is ambiguous")]
    PostAmbiguous,
    /// Kernel or injected entropy failed.
    #[error("request identifier entropy failed")]
    Entropy,
    /// Durable journaling failed.
    #[error("request identifier journal failed")]
    Journal,
    /// Effective-base persistence failed.
    #[error("effective provisioning base persistence failed")]
    Store,
    /// The generated identifier was already journaled.
    #[error("request identifier collision")]
    RequestIdCollision,
}

impl From<ConfigError> for ClientError {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::InvalidValue | ConfigError::InvalidResponse => Self::InvalidResponse,
            ConfigError::InvalidBaseUrl => Self::InvalidBaseUrl,
            ConfigError::ChallengeSize => Self::ChallengeSize,
        }
    }
}

/// Provisioning request state machine over injected closed boundaries.
#[derive(Debug)]
pub struct ProvisioningHttpClient<T, S, E, J> {
    snapshot_base: BaseUrl,
    effective_base: BaseUrl,
    transport: T,
    store: S,
    entropy: E,
    journal: J,
}

impl<T: HttpTransport, S: EffectiveBaseStore, E: EntropySource, J: AttemptJournal>
    ProvisioningHttpClient<T, S, E, J>
{
    /// Creates a client, honoring only a previously validated module-owned base.
    pub fn new(snapshot_base: BaseUrl, boundaries: (T, S, E, J)) -> Self {
        let (transport, store, entropy, journal) = boundaries;
        let effective_base = store.load().unwrap_or_else(|| snapshot_base.clone());
        Self {
            snapshot_base,
            effective_base,
            transport,
            store,
            entropy,
            journal,
        }
    }

    /// Fetches a challenge/configuration from the snapshotted donor base.
    pub fn fetch(&mut self, info: &ProvisioningInfo) -> Result<FetchConfiguration, ClientError> {
        let url = format!("{}/:fetchEekChain", self.snapshot_base);
        let body = info.to_cbor()?;
        let response = self.transport.post(HttpRequest {
            url: &url,
            headers: &[
                ("Accept", "application/cbor"),
                ("Content-Type", "application/cbor"),
            ],
            body: &body,
        })?;
        validate_response(&response)?;
        let (challenge, override_url) = parse_fetch_response(response.body())?;
        if let Some(base) = override_url {
            self.store.store(&base).map_err(|_| ClientError::Store)?;
            self.effective_base = base;
        }
        Ok(FetchConfiguration {
            challenge,
            effective_base: self.effective_base.clone(),
        })
    }

    /// Posts one Task-18 body after durably recording a fresh `UUIDv4`.
    pub fn sign(&mut self, body: &[u8], challenge: &[u8]) -> Result<HttpResponse, ClientError> {
        self.sign_with_request_id(body, challenge)
            .map(|signed| signed.response)
    }

    /// Posts one Task-18 body and returns its durably journaled request identifier.
    pub fn sign_with_request_id(
        &mut self,
        body: &[u8],
        challenge: &[u8],
    ) -> Result<SignedCertificateResponse, ClientError> {
        if body.len() > MAX_PROVISIONING_BYTES {
            return Err(ClientError::RequestTooLarge);
        }
        if !(16..=MAX_CHALLENGE_BYTES).contains(&challenge.len()) {
            return Err(ClientError::ChallengeSize);
        }
        let mut random = [0_u8; 16];
        self.entropy.fill_uuid(&mut random)?;
        random[6] = (random[6] & 0x0f) | 0x40;
        random[8] = (random[8] & 0x3f) | 0x80;
        let request_id = uuid(&random);
        if !self
            .journal
            .record(&request_id)
            .map_err(|_| ClientError::Journal)?
        {
            return Err(ClientError::RequestIdCollision);
        }
        let url = format!(
            "{}/:signCertificates?challenge={}",
            self.effective_base,
            base64_url(challenge)
        );
        let send = |transport: &mut T| {
            transport.post(HttpRequest {
                url: &url,
                headers: &[
                    ("Accept", "application/cbor"),
                    ("Content-Type", "application/cbor"),
                ],
                body,
            })
        };
        let response = match send(&mut self.transport) {
            Err(ClientError::ConnectBeforeUpload)
                if FailureDisposition::classify(
                    UploadProgress::NoRequestByteWritten,
                    PostFailure::Connect,
                ) == FailureDisposition::Retryable =>
            {
                send(&mut self.transport)?
            }
            result => result?,
        };
        validate_response(&response)?;
        Ok(SignedCertificateResponse {
            request_id,
            response,
        })
    }

    #[cfg(test)]
    const fn transport(&self) -> &T {
        &self.transport
    }
    #[cfg(test)]
    const fn store(&self) -> &S {
        &self.store
    }
}

fn validate_response(response: &HttpResponse) -> Result<(), ClientError> {
    if (300..400).contains(&response.status()) || response.headers.has_location() {
        return Err(ClientError::Redirect);
    }
    if !(200..300).contains(&response.status()) {
        return Err(ClientError::HttpStatus);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::config::{BaseUrl, ProvisioningInfo};

    #[test]
    fn challenge_builds_pinned_fetch_and_sign_requests() {
        let order = Rc::new(RefCell::new(Vec::new()));
        let transport = FakeTransport::with_order(
            vec![
                HttpResponse::ok(fetch_response(
                    &[0xfb; 16],
                    Some("https://override.example/v2"),
                )),
                HttpResponse::ok(fetch_response(&[0xfb; 16], None)),
                HttpResponse::ok(Vec::new()),
            ],
            Rc::clone(&order),
        );
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://snapshot.example/v1").unwrap(),
            (
                transport,
                MemoryStore::default(),
                FixedEntropy::new([0; 16]),
                MemoryJournal::with_order(Rc::clone(&order)),
            ),
        );

        client
            .fetch(&ProvisioningInfo::new("fp", 42, 16).unwrap())
            .unwrap();
        let fetched = client
            .fetch(&ProvisioningInfo::new("fp", 42, 16).unwrap())
            .unwrap();
        order.borrow_mut().clear();
        client.sign(&[1, 2, 3], &fetched.challenge).unwrap();

        let calls = client.transport().calls();
        let [fetch_one, fetch_two, sign] = calls else {
            panic!("expected two fetches and one signing upload");
        };
        assert_eq!(fetch_one.url, "https://snapshot.example/v1/:fetchEekChain");
        assert_eq!(
            fetch_one.headers,
            vec![
                ("Accept".into(), "application/cbor".into()),
                ("Content-Type".into(), "application/cbor".into()),
            ]
        );
        assert_eq!(
            sign.url,
            "https://override.example/v2/:signCertificates?challenge=-_v7-_v7-_v7-_v7-_v7-w"
        );
        assert_eq!(fetch_two.url, "https://snapshot.example/v1/:fetchEekChain");
        assert_eq!(sign.body, vec![1, 2, 3]);
        assert_eq!(
            client.store().loaded().unwrap().as_str(),
            "https://override.example/v2"
        );
        assert_eq!(&*order.borrow(), &["journal", "upload"]);
    }

    #[test]
    fn challenge_generates_fresh_uuid_and_rejects_collision_before_upload() {
        let mut entropy = FixedEntropy::new([1; 16]);
        entropy.push([2; 16]);
        entropy.push([2; 16]);
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                FakeTransport::new(vec![
                    HttpResponse::ok(Vec::new()),
                    HttpResponse::ok(Vec::new()),
                ]),
                MemoryStore::default(),
                entropy,
                MemoryJournal::default(),
            ),
        );
        let challenge = [3; 16];

        let first_id = client
            .sign_with_request_id(&[], &challenge)
            .unwrap()
            .request_id()
            .to_owned();
        let second_id = client
            .sign_with_request_id(&[], &challenge)
            .unwrap()
            .request_id()
            .to_owned();
        let error = client.sign(&[], &challenge).unwrap_err();

        assert_eq!(error, ClientError::RequestIdCollision);
        assert_ne!(first_id, second_id);
        let [first, second] = client.transport().calls() else {
            panic!("expected exactly two uploads");
        };
        assert_eq!(first.url, second.url);
    }

    #[test]
    fn proven_zero_byte_connect_retry_reuses_the_exact_request() {
        let mut transport = FakeTransport::new(vec![HttpResponse::ok(Vec::new())]);
        transport.connect_failures = 1;
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                transport,
                MemoryStore::default(),
                FixedEntropy::new([9; 16]),
                MemoryJournal::default(),
            ),
        );

        client.sign(&[1, 2], &[3; 16]).unwrap();

        let [first, second] = client.transport().calls() else {
            panic!("expected exact one retry");
        };
        assert_eq!(first.url, second.url);
        assert_eq!(first.body, second.body);
    }

    #[test]
    fn reject_redirect_downgrade() {
        let redirect = response(302, [("location", "http://attacker.example")], Vec::new());
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                FakeTransport::new(vec![redirect]),
                MemoryStore::default(),
                FixedEntropy::new([0; 16]),
                MemoryJournal::default(),
            ),
        );

        let error = client
            .fetch(&ProvisioningInfo::new("fp", 42, 16).unwrap())
            .unwrap_err();

        assert_eq!(error, ClientError::Redirect);
        assert!(client.store().loaded().is_none());
    }

    #[test]
    fn invalid_override_is_closed_without_store_mutation() {
        let response = fetch_response(&[4; 16], Some("http://rkp.example"));
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                FakeTransport::new(vec![HttpResponse::ok(response)]),
                MemoryStore::default(),
                FixedEntropy::new([0; 16]),
                MemoryJournal::default(),
            ),
        );

        assert_eq!(
            client
                .fetch(&ProvisioningInfo::new("fp", 42, 16).unwrap())
                .unwrap_err(),
            ClientError::InvalidBaseUrl
        );
        assert!(client.store().loaded().is_none());
    }

    #[test]
    fn challenge_and_body_bounds_are_enforced() {
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                FakeTransport::new(Vec::new()),
                MemoryStore::default(),
                FixedEntropy::new([0; 16]),
                MemoryJournal::default(),
            ),
        );
        assert_eq!(client.sign(&[], &[0; 15]), Err(ClientError::ChallengeSize));
        assert_eq!(
            client.sign(&vec![0; crate::MAX_PROVISIONING_BYTES + 1], &[0; 16]),
            Err(ClientError::RequestTooLarge)
        );
        assert!(client.transport().calls().is_empty());
    }

    #[test]
    fn journal_failure_prevents_upload() {
        let mut client = ProvisioningHttpClient::new(
            BaseUrl::parse("https://rkp.example").unwrap(),
            (
                FakeTransport::new(Vec::new()),
                MemoryStore::default(),
                FixedEntropy::new([0; 16]),
                FailingJournal,
            ),
        );

        assert_eq!(client.sign(&[], &[0; 16]), Err(ClientError::Journal));
        assert!(client.transport().calls().is_empty());
    }

    #[test]
    fn response_policy_rejects_location_status_and_oversize() {
        for response in [
            response(200, [("location", "https://other.example")], Vec::new()),
            response(500, std::iter::empty::<(&str, &str)>(), Vec::new()),
        ] {
            let mut client = ProvisioningHttpClient::new(
                BaseUrl::parse("https://rkp.example").unwrap(),
                (
                    FakeTransport::new(vec![response]),
                    MemoryStore::default(),
                    FixedEntropy::new([0; 16]),
                    MemoryJournal::default(),
                ),
            );
            assert!(
                client
                    .fetch(&ProvisioningInfo::new("fp", 42, 16).unwrap())
                    .is_err()
            );
            assert!(client.store().loaded().is_none());
        }
        assert_eq!(
            HttpResponse::new(
                200,
                ResponseHeaders::collect_bounded(std::iter::empty::<(&str, &str)>()).unwrap(),
                vec![0; crate::MAX_PROVISIONING_BYTES + 1],
            ),
            Err(ClientError::ResponseTooLarge)
        );
    }

    fn response<I, N, V>(status: u16, headers: I, body: Vec<u8>) -> HttpResponse
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        HttpResponse::new(
            status,
            ResponseHeaders::collect_bounded(headers).unwrap(),
            body,
        )
        .unwrap()
    }

    fn fetch_response(challenge: &[u8], url: Option<&str>) -> Vec<u8> {
        let mut body = vec![if url.is_some() { 0x83 } else { 0x82 }, 0x80];
        body.push(u8::try_from(challenge.len()).unwrap() | 0x40);
        body.extend_from_slice(challenge);
        if let Some(url) = url {
            body.push(0xa1);
            body.push(0x70);
            body.extend_from_slice(b"provisioning_url");
            body.extend_from_slice(&[0x78, u8::try_from(url.len()).unwrap()]);
            body.extend_from_slice(url.as_bytes());
        }
        body
    }

    #[derive(Default)]
    struct MemoryStore(Option<BaseUrl>);
    impl EffectiveBaseStore for MemoryStore {
        fn load(&self) -> Option<BaseUrl> {
            self.0.clone()
        }
        fn store(&mut self, base: &BaseUrl) -> Result<(), ClientError> {
            self.0 = Some(base.clone());
            Ok(())
        }
    }
    impl MemoryStore {
        fn loaded(&self) -> Option<BaseUrl> {
            self.load()
        }
    }

    #[derive(Default)]
    struct MemoryJournal {
        ids: Vec<String>,
        order: Option<Rc<RefCell<Vec<&'static str>>>>,
    }
    impl AttemptJournal for MemoryJournal {
        fn record(&mut self, id: &str) -> Result<bool, ClientError> {
            if let Some(order) = &self.order {
                order.borrow_mut().push("journal");
            }
            if self.ids.iter().any(|seen| seen == id) {
                return Ok(false);
            }
            self.ids.push(id.to_owned());
            Ok(true)
        }
    }
    struct FailingJournal;
    impl AttemptJournal for FailingJournal {
        fn record(&mut self, _id: &str) -> Result<bool, ClientError> {
            Err(ClientError::Journal)
        }
    }
    impl MemoryJournal {
        fn with_order(order: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                ids: Vec::new(),
                order: Some(order),
            }
        }
    }

    struct FixedEntropy(Vec<[u8; 16]>);
    impl FixedEntropy {
        fn new(bytes: [u8; 16]) -> Self {
            Self(vec![bytes])
        }
        fn push(&mut self, bytes: [u8; 16]) {
            self.0.insert(0, bytes);
        }
    }
    impl EntropySource for FixedEntropy {
        fn fill_uuid(&mut self, output: &mut [u8; 16]) -> Result<(), ClientError> {
            *output = self.0.pop().ok_or(ClientError::Entropy)?;
            Ok(())
        }
    }

    struct FakeTransport {
        responses: Vec<HttpResponse>,
        calls: Vec<OwnedRequest>,
        order: Option<Rc<RefCell<Vec<&'static str>>>>,
        connect_failures: usize,
    }
    impl FakeTransport {
        fn new(mut responses: Vec<HttpResponse>) -> Self {
            responses.reverse();
            Self {
                responses,
                calls: Vec::new(),
                order: None,
                connect_failures: 0,
            }
        }
        fn with_order(
            mut responses: Vec<HttpResponse>,
            order: Rc<RefCell<Vec<&'static str>>>,
        ) -> Self {
            responses.reverse();
            Self {
                responses,
                calls: Vec::new(),
                order: Some(order),
                connect_failures: 0,
            }
        }
        fn calls(&self) -> &[OwnedRequest] {
            &self.calls
        }
    }
    impl HttpTransport for FakeTransport {
        fn post(&mut self, request: HttpRequest<'_>) -> Result<HttpResponse, ClientError> {
            if let Some(order) = &self.order {
                order.borrow_mut().push("upload");
            }
            self.calls.push(OwnedRequest {
                url: request.url.to_owned(),
                headers: request
                    .headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
                body: request.body.to_vec(),
            });
            if self.connect_failures > 0 {
                self.connect_failures = self.connect_failures.saturating_sub(1);
                return Err(ClientError::ConnectBeforeUpload);
            }
            self.responses.pop().ok_or(ClientError::Transport)
        }
    }
    struct OwnedRequest {
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }
}
