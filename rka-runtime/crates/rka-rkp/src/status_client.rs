use std::{collections::BTreeMap, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, Visitor},
};

use crate::{
    ClientError, HttpResponse, StatusSnapshot, ValidationError, status::CertificateStatus,
};
use thiserror::Error;

/// Closed, secret-free failure categories for the production status fetch and parser.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum StatusClientError {
    /// A requested serial was not canonical hexadecimal.
    #[error("status serial rejected")]
    Serial,
    /// The bounded HTTPS transport failed.
    #[error("status transport failed: {0}")]
    Transport(ClientError),
    /// HTTP status or redirect policy was rejected.
    #[error("status HTTP response rejected")]
    Http,
    /// Cache-Control was missing, ambiguous, or invalid.
    #[error("status cache policy rejected")]
    CachePolicy,
    /// The JSON document did not match the closed schema.
    #[error("status document rejected")]
    Document,
    /// A status entry was not canonical.
    #[error("status entry rejected")]
    Entry,
    /// The bounded status snapshot could not be constructed.
    #[error("status snapshot rejected")]
    Snapshot,
}

/// Fixed bounded GET request for Android attestation status.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct StatusRequest<'a> {
    /// Exact HTTPS URL.
    pub url: &'a str,
    /// Exact request headers.
    pub headers: &'a [(&'a str, &'a str)],
}

/// Closed transport boundary for status retrieval with redirects disabled.
pub trait StatusHttpTransport {
    /// Sends one bounded GET request.
    fn get(&mut self, request: StatusRequest<'_>) -> Result<HttpResponse, ClientError>;
}

/// Fetches and caches Google's complete attestation revocation document.
#[derive(Debug)]
pub struct AttestationStatusClient<T> {
    transport: T,
    cached: Option<CachedStatus>,
}

#[derive(Debug)]
struct CachedStatus {
    fetched_at: u64,
    max_age: u64,
    revoked: BTreeMap<String, CertificateStatus>,
}

impl<T: StatusHttpTransport> AttestationStatusClient<T> {
    /// Creates a status client over a redirect-disabled transport.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            cached: None,
        }
    }

    /// Resolves an authoritative status for every requested certificate serial.
    pub fn snapshot_for<'a>(
        &mut self,
        now: u64,
        serials: impl IntoIterator<Item = &'a str>,
    ) -> Result<StatusSnapshot, ValidationError> {
        self.snapshot_for_diagnostic(now, serials)
            .map_err(|_| ValidationError::Status)
    }

    /// Resolves statuses while retaining only a closed production-safe failure category.
    pub fn snapshot_for_diagnostic<'a>(
        &mut self,
        now: u64,
        serials: impl IntoIterator<Item = &'a str>,
    ) -> Result<StatusSnapshot, StatusClientError> {
        let serials = serials
            .into_iter()
            .map(normalize_serial)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StatusClientError::Serial)?;
        if !self
            .cached
            .as_ref()
            .is_some_and(|cached| cached.is_fresh(now))
        {
            self.cached = Some(self.fetch(now)?);
        }
        let cached = self.cached.as_ref().ok_or(StatusClientError::Snapshot)?;
        let entries = serials.into_iter().map(|serial| {
            let status = cached
                .revoked
                .get(&serial)
                .copied()
                .unwrap_or(CertificateStatus::Good);
            (serial, status)
        });
        StatusSnapshot::new(
            cached.fetched_at,
            &format!("max-age={}", cached.max_age),
            entries,
        )
        .map_err(|_| StatusClientError::Snapshot)
    }

    #[doc(hidden)]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    fn fetch(&mut self, now: u64) -> Result<CachedStatus, StatusClientError> {
        let response = self
            .transport
            .get(StatusRequest {
                url: crate::STATUS_URL,
                headers: &[("Accept", "application/json")],
            })
            .map_err(StatusClientError::Transport)?;
        if response.status() != 200 || response.headers().has_location() {
            return Err(StatusClientError::Http);
        }
        let cache_control = response
            .headers()
            .unique_value("cache-control")
            .ok_or(StatusClientError::CachePolicy)?;
        let max_age = crate::status::parse_max_age(cache_control)
            .map_err(|_| StatusClientError::CachePolicy)?;
        let document: StatusDocument =
            serde_json::from_slice(response.body()).map_err(|_| StatusClientError::Document)?;
        document.validate().map_err(|_| StatusClientError::Entry)?;
        Ok(CachedStatus {
            fetched_at: now,
            max_age,
            revoked: document
                .entries
                .into_keys()
                .map(|serial| (serial, CertificateStatus::Revoked))
                .collect(),
        })
    }
}

impl CachedStatus {
    const fn is_fresh(&self, now: u64) -> bool {
        now >= self.fetched_at && now.saturating_sub(self.fetched_at) < self.max_age
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusDocument {
    #[serde(deserialize_with = "deserialize_entries")]
    entries: BTreeMap<String, RevocationEntry>,
}

impl StatusDocument {
    fn validate(&self) -> Result<(), ValidationError> {
        for (serial, entry) in &self.entries {
            let normalized = normalize_serial(serial)?;
            if &normalized != serial {
                return Err(ValidationError::Status);
            }
            if entry
                .comment
                .as_ref()
                .is_some_and(|value| value.len() > 140)
                || entry
                    .expires
                    .as_ref()
                    .is_some_and(|value| !valid_date(value))
            {
                return Err(ValidationError::Status);
            }
            match entry.status {
                RevocationState::Revoked | RevocationState::Suspended => {}
            }
            if let Some(reason) = entry.reason {
                match reason {
                    RevocationReason::Unspecified
                    | RevocationReason::KeyCompromise
                    | RevocationReason::CaCompromise
                    | RevocationReason::Superseded
                    | RevocationReason::SoftwareFlaw => {}
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationEntry {
    status: RevocationState,
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    reason: Option<RevocationReason>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RevocationState {
    Revoked,
    Suspended,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    Superseded,
    SoftwareFlaw,
}

fn deserialize_entries<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, RevocationEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EntriesVisitor(PhantomData<fn() -> BTreeMap<String, RevocationEntry>>);
    impl<'de> Visitor<'de> for EntriesVisitor {
        type Value = BTreeMap<String, RevocationEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a unique serial-to-status map")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some((serial, entry)) = map.next_entry::<String, RevocationEntry>()? {
                if entries.insert(serial, entry).is_some() {
                    return Err(A::Error::custom("duplicate certificate serial"));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(EntriesVisitor(PhantomData))
}

fn normalize_serial(serial: &str) -> Result<String, ValidationError> {
    let normalized = serial.trim_start_matches('0').to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationError::Status);
    }
    Ok(normalized)
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}
