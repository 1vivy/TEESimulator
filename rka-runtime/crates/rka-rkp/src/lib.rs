//! Host-testable boundary for remote key provisioning.

use thiserror::Error;

/// Maximum request or response body accepted by the provisioning adapter.
pub const MAX_PROVISIONING_BYTES: usize = 1_048_576;
/// Maximum response header count.
pub const MAX_HEADER_COUNT: usize = 64;
/// Maximum bytes in one canonical response header name.
pub const MAX_HEADER_NAME_BYTES: usize = 128;
/// Maximum bytes in one response header value.
pub const MAX_HEADER_VALUE_BYTES: usize = 4096;
/// Maximum aggregate bytes across response header names and values.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Bounded response-header parsing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HeaderError {
    /// Too many headers were supplied.
    #[error("response header count exceeds the fixed boundary")]
    Count,
    /// A header name was oversized or noncanonical.
    #[error("response header name is invalid")]
    Name,
    /// A header value was oversized or invalid.
    #[error("response header value is invalid")]
    Value,
    /// Aggregate header bytes exceeded the fixed boundary.
    #[error("response headers exceed the aggregate boundary")]
    Aggregate,
    /// More than one Location header was supplied.
    #[error("response contains ambiguous Location headers")]
    DuplicateLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    name: String,
    value: String,
}

/// Validated response headers bounded before storage or scanning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeaders(Vec<Header>);

impl ResponseHeaders {
    /// Validates and stores a bounded stream of response headers.
    pub fn collect_bounded<I, N, V>(headers: I) -> Result<Self, HeaderError>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mut stored = Vec::new();
        let mut total = 0_usize;
        let mut location_seen = false;
        for (name, value) in headers {
            if stored.len() == MAX_HEADER_COUNT {
                return Err(HeaderError::Count);
            }
            let name = name.as_ref();
            let value = value.as_ref();
            if !valid_header_name(name) {
                return Err(HeaderError::Name);
            }
            if !valid_header_value(value) {
                return Err(HeaderError::Value);
            }
            total = checked_header_total(total, name.len())?;
            total = checked_header_total(total, value.len())?;
            if name == "location" && std::mem::replace(&mut location_seen, true) {
                return Err(HeaderError::DuplicateLocation);
            }
            stored.push(Header {
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
        Ok(Self(stored))
    }

    pub(crate) fn has_location(&self) -> bool {
        self.0.iter().any(|header| header.name == "location")
    }

    pub(crate) fn unique_value(&self, name: &str) -> Option<&str> {
        let mut values = self
            .0
            .iter()
            .filter(|header| header.name == name)
            .map(|header| header.value.as_str());
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HEADER_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_header_value(value: &str) -> bool {
    value.len() <= MAX_HEADER_VALUE_BYTES
        && value.bytes().all(|byte| matches!(byte, b' '..=b'~'))
        && (value.is_empty() || value.trim_ascii() == value)
}

pub(crate) const fn checked_header_total(
    total: usize,
    additional: usize,
) -> Result<usize, HeaderError> {
    match total.checked_add(additional) {
        Some(sum) if sum <= MAX_HEADER_BYTES => Ok(sum),
        Some(_) | None => Err(HeaderError::Aggregate),
    }
}

pub(crate) fn uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub(crate) fn base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let value = (u32::from(*chunk.first().unwrap_or(&0)) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18_u32, 12, 6, 0]
            .into_iter()
            .take(chunk.len().saturating_add(1))
        {
            let index = ((value >> shift) & 63) as usize;
            output.push(char::from(*TABLE.get(index).unwrap_or(&b'A')));
        }
    }
    output
}

/// Platform-independent provisioning adapter.
pub trait ProvisioningClient {
    /// Exchanges one bounded request and writes into caller-owned storage.
    fn exchange(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ProvisioningError>;
}

/// Provisioning boundary failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningError {
    /// A request crossed the fixed network boundary.
    #[error("provisioning request is {actual} bytes; maximum is {maximum}")]
    RequestTooLarge {
        /// Observed byte count.
        actual: usize,
        /// Accepted byte count.
        maximum: usize,
    },
    /// The caller-provided response storage is insufficient.
    #[error("response capacity is {actual} bytes; required is {required}")]
    ResponseCapacity {
        /// Available storage.
        actual: usize,
        /// Required storage.
        required: usize,
    },
    /// The platform adapter reported a transport failure.
    #[error("provisioning transport failed")]
    Transport,
}

/// Checks a provisioning request before a platform adapter receives it.
pub const fn validate_request(request: &[u8]) -> Result<(), ProvisioningError> {
    if request.len() > MAX_PROVISIONING_BYTES {
        return Err(ProvisioningError::RequestTooLarge {
            actual: request.len(),
            maximum: MAX_PROVISIONING_BYTES,
        });
    }
    Ok(())
}

mod activation;
mod chain;
pub mod challenge;
pub mod config;
mod csr;
mod https;
/// Durable classification and local replay for provisioning POSTs.
pub mod outcome;
mod response;
mod status;
mod status_client;
mod trust;
mod trust_session;
mod validation;

pub use activation::{ActivationError, activate_validated_response};
pub use chain::returned_serials;
pub use challenge::{ClientError, HttpResponse, SignedCertificateResponse};
pub use csr::{PreparedCertificateRequest, assemble_android_v3_body};
pub use https::BoundedHttpsTransport;
pub use response::parse_signed_certificates;
pub use status::{CertificateStatus, STATUS_URL, StatusSnapshot};
pub use status_client::{
    AttestationStatusClient, StatusClientError, StatusHttpTransport, StatusRequest,
};
pub use trust::{GOOGLE_ROOT_HASHES, GOOGLE_ROOTS_DER, RootBundle, RootRotationAuthorization};
pub use trust_session::{ProvisioningSession, RootTrustManager, TrustSessionError};
pub use validation::{
    ExpectedKey, ResponseContext, ValidatedChain, ValidatedResponse, ValidationError,
    validate_response,
};

#[cfg(test)]
mod tests {
    use super::{
        HeaderError, MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_HEADER_NAME_BYTES,
        MAX_HEADER_VALUE_BYTES, MAX_PROVISIONING_BYTES, ProvisioningError, ResponseHeaders,
        checked_header_total, validate_request,
    };

    #[test]
    fn oversized_request_is_rejected_before_transport() {
        let request = vec![0_u8; MAX_PROVISIONING_BYTES + 1];
        let result = validate_request(&request);

        assert_eq!(
            result,
            Err(ProvisioningError::RequestTooLarge {
                actual: MAX_PROVISIONING_BYTES + 1,
                maximum: MAX_PROVISIONING_BYTES,
            })
        );
    }

    #[test]
    fn response_headers_accept_every_exact_boundary() {
        let count = (0..MAX_HEADER_COUNT).map(|index| (format!("x-{index}"), String::new()));
        assert!(ResponseHeaders::collect_bounded(count).is_ok());
        assert!(
            ResponseHeaders::collect_bounded([("a".repeat(MAX_HEADER_NAME_BYTES), "")]).is_ok()
        );
        assert!(
            ResponseHeaders::collect_bounded([("x", "a".repeat(MAX_HEADER_VALUE_BYTES))]).is_ok()
        );
        let aggregate = [('a', 4095), ('b', 4095), ('c', 4095), ('d', 4095)]
            .map(|(name, length)| (name.to_string(), "a".repeat(length)));
        assert!(ResponseHeaders::collect_bounded(aggregate).is_ok());
    }

    #[test]
    fn response_headers_reject_each_boundary_plus_one() {
        let count = (0..=MAX_HEADER_COUNT).map(|index| (format!("x-{index}"), String::new()));
        assert_eq!(
            ResponseHeaders::collect_bounded(count),
            Err(HeaderError::Count)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([("a".repeat(MAX_HEADER_NAME_BYTES + 1), "")]),
            Err(HeaderError::Name)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([("x", "a".repeat(MAX_HEADER_VALUE_BYTES + 1))]),
            Err(HeaderError::Value)
        );
        let aggregate = [('a', 4096), ('b', 4096), ('c', 4096), ('d', 4096)]
            .map(|(name, length)| (name.to_string(), "a".repeat(length)));
        assert_eq!(
            ResponseHeaders::collect_bounded(aggregate),
            Err(HeaderError::Aggregate)
        );
        assert_eq!(
            checked_header_total(usize::MAX, 1),
            Err(HeaderError::Aggregate)
        );
        assert_eq!(MAX_HEADER_BYTES, 16 * 1024);
    }

    #[test]
    fn response_headers_reject_invalid_and_ambiguous_values() {
        assert_eq!(
            ResponseHeaders::collect_bounded([("Location", "https://rkp.example")]),
            Err(HeaderError::Name)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([("x", "ok\r\ninjected")]),
            Err(HeaderError::Value)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([("x", " padded")]),
            Err(HeaderError::Value)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([
                ("location", "https://one.example"),
                ("location", "https://two.example"),
            ]),
            Err(HeaderError::DuplicateLocation)
        );
        assert_eq!(
            ResponseHeaders::collect_bounded([(
                "location",
                "a".repeat(MAX_HEADER_VALUE_BYTES + 1),
            )]),
            Err(HeaderError::Value)
        );
        let many_small = (0..MAX_HEADER_COUNT).map(|index| (format!("x-{index}"), "a".repeat(256)));
        assert_eq!(
            ResponseHeaders::collect_bounded(many_small),
            Err(HeaderError::Aggregate)
        );
    }
}
