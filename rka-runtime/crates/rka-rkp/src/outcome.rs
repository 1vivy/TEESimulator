//! Durable classification and local replay for non-idempotent provisioning POSTs.

use std::fmt;

use ring::digest::{SHA256, digest};
use rka_state::{MAX_STATE_BYTES, StateError, StateStore, validate_record};
use thiserror::Error;

const RESPONSE_KEY: &[u8] = b"rkp-post-response-v1";
const POSTING_KEY: &[u8] = b"rkp-posting-v1";
const MAX_HANDLES: usize = 20;

/// Exact identity of one non-idempotent provisioning attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptIdentity {
    request_id: [u8; 16],
    batch_id: [u8; 16],
    challenge_hash: [u8; 32],
    csr_hash: [u8; 32],
    handles: Vec<[u8; 32]>,
}

/// Request and batch identifiers for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptIds {
    request_id: [u8; 16],
    batch_id: [u8; 16],
}

impl AttemptIds {
    /// Creates the exact request and batch identifier pair.
    #[must_use]
    pub const fn new(request_id: [u8; 16], batch_id: [u8; 16]) -> Self {
        Self {
            request_id,
            batch_id,
        }
    }
}

/// Challenge and CSR digests for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptDigests {
    challenge_hash: [u8; 32],
    csr_hash: [u8; 32],
}

impl AttemptDigests {
    /// Creates the exact challenge and CSR digest pair.
    #[must_use]
    pub const fn new(challenge_hash: [u8; 32], csr_hash: [u8; 32]) -> Self {
        Self {
            challenge_hash,
            csr_hash,
        }
    }
}

impl AttemptIdentity {
    /// Parses a complete attempt identity at the trust boundary.
    pub fn new(
        ids: AttemptIds,
        digests: AttemptDigests,
        handles: Vec<[u8; 32]>,
    ) -> Result<Self, OutcomeError> {
        if handles.is_empty()
            || handles.len() > MAX_HANDLES
            || handles.iter().enumerate().any(|(index, handle)| {
                handles
                    .get(..index)
                    .is_some_and(|prior| prior.contains(handle))
            })
        {
            return Err(OutcomeError::Identity);
        }
        Ok(Self {
            request_id: ids.request_id,
            batch_id: ids.batch_id,
            challenge_hash: digests.challenge_hash,
            csr_hash: digests.csr_hash,
            handles,
        })
    }

    /// Returns the bound challenge digest.
    #[must_use]
    pub const fn challenge_hash(&self) -> &[u8; 32] {
        &self.challenge_hash
    }

    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the exact batch identifier.
    #[must_use]
    pub const fn batch_id(&self) -> &[u8; 16] {
        &self.batch_id
    }

    /// Returns the exact mapped handles.
    #[must_use]
    pub fn handles(&self) -> &[[u8; 32]] {
        &self.handles
    }
}

/// Durable identity boundary written before a non-idempotent upload begins.
pub struct DurablePostingJournal<'a> {
    store: &'a dyn StateStore,
}

impl<'a> DurablePostingJournal<'a> {
    /// Binds the posting journal to its durable state store.
    #[must_use]
    pub const fn new(store: &'a dyn StateStore) -> Self {
        Self { store }
    }

    /// Loads the most recent upload identity.
    pub fn load(&self) -> Result<Option<AttemptIdentity>, OutcomeError> {
        let Some(bytes) = read_optional(self.store, POSTING_KEY)? else {
            return Ok(None);
        };
        let (identity, response) = decode(&bytes)?;
        if !response.is_empty() {
            return Err(OutcomeError::Corrupt);
        }
        Ok(Some(identity))
    }

    /// Persists the exact identity before the transport is invoked.
    pub fn record(&self, identity: &AttemptIdentity) -> Result<(), OutcomeError> {
        let encoded = encode(identity, &[])?;
        validate_record(&encoded)?;
        self.store.replace(POSTING_KEY, &encoded)?;
        Ok(())
    }
}

impl fmt::Debug for DurablePostingJournal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurablePostingJournal")
            .finish_non_exhaustive()
    }
}

/// Furthest point definitely reached by the POST transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UploadProgress {
    /// Connection setup failed before the first request byte.
    NoRequestByteWritten,
    /// At least one request byte may have reached the peer.
    UploadMayHaveBegun,
    /// The complete request was written but no durable response is available.
    UploadCompleted,
}

/// Observable transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PostFailure {
    /// Connection establishment failed.
    Connect,
    /// A bounded operation timed out.
    Timeout,
    /// Upload completed but the response was lost.
    LostResponse,
    /// The sidecar died during the exchange.
    SidecarDeath,
    /// A complete response was not durably recorded.
    MissingDurableResponse,
    /// DNS resolution failed.
    Dns,
    /// TLS negotiation failed.
    Tls,
    /// Request encoding failed locally.
    Encode,
    /// A local I/O or process boundary failed.
    Local,
    /// Configuration was rejected locally.
    Config,
}

/// Fail-closed outcome of a POST failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FailureDisposition {
    /// Safe to start a new connection for the same not-yet-uploaded request.
    Retryable,
    /// Upload may have occurred; the entire attempt must be quarantined.
    PostAmbiguous,
}

impl FailureDisposition {
    /// Classifies solely from the transport's proven upload boundary.
    #[must_use]
    pub const fn classify(progress: UploadProgress, failure: PostFailure) -> Self {
        match (progress, failure) {
            (UploadProgress::NoRequestByteWritten, PostFailure::Connect) => Self::Retryable,
            _ => Self::PostAmbiguous,
        }
    }
}

/// Ensures every identity and key handle changes after an ambiguous attempt.
pub fn validate_fresh_attempt(
    previous: &AttemptIdentity,
    next: &AttemptIdentity,
) -> Result<(), OutcomeError> {
    let fresh = previous.request_id != next.request_id
        && previous.batch_id != next.batch_id
        && previous.challenge_hash != next.challenge_hash
        && previous.csr_hash != next.csr_hash
        && previous
            .handles
            .iter()
            .all(|handle| !next.handles.contains(handle));
    if fresh {
        Ok(())
    } else {
        Err(OutcomeError::IdentityReuse)
    }
}

/// Durable local replay boundary for a fully validated response.
pub struct DurableResponseJournal<'a> {
    store: &'a dyn StateStore,
}

impl<'a> DurableResponseJournal<'a> {
    /// Binds a journal to its durable state store.
    #[must_use]
    pub const fn new(store: &'a dyn StateStore) -> Self {
        Self { store }
    }

    /// Records the complete validated response before it can be replayed.
    pub fn record_validated(
        &self,
        identity: &AttemptIdentity,
        response: &[u8],
    ) -> Result<(), OutcomeError> {
        let encoded = encode(identity, response)?;
        validate_record(&encoded)?;
        self.store.replace(RESPONSE_KEY, &encoded)?;
        Ok(())
    }

    /// Returns a local response only when every request identity field matches.
    pub fn replay_for(&self, identity: &AttemptIdentity) -> Result<Option<Vec<u8>>, OutcomeError> {
        let Some(stored) = read_optional(self.store, RESPONSE_KEY)? else {
            return Ok(None);
        };
        let (bound, response) = decode(&stored)?;
        if &bound != identity {
            return Err(OutcomeError::StaleReplay);
        }
        Ok(Some(response))
    }
}

fn read_optional(store: &dyn StateStore, key: &[u8]) -> Result<Option<Vec<u8>>, OutcomeError> {
    let mut stored = vec![0_u8; MAX_STATE_BYTES];
    let size = match store.read(key, &mut stored) {
        Ok(size) => size,
        Err(StateError::Missing) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    stored.truncate(size);
    Ok(Some(stored))
}

impl fmt::Debug for DurableResponseJournal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableResponseJournal")
            .finish_non_exhaustive()
    }
}

/// POST outcome persistence failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OutcomeError {
    /// Attempt fields or handles are invalid.
    #[error("attempt identity is invalid")]
    Identity,
    /// A field or handle from an ambiguous attempt was reused.
    #[error("ambiguous attempt identity was reused")]
    IdentityReuse,
    /// Stored bytes do not match the canonical authenticated schema.
    #[error("durable response is corrupt")]
    Corrupt,
    /// Stored bytes are bound to another attempt.
    #[error("durable response belongs to another request")]
    StaleReplay,
    /// The durable state boundary failed.
    #[error(transparent)]
    State(#[from] StateError),
}

fn encode(identity: &AttemptIdentity, response: &[u8]) -> Result<Vec<u8>, OutcomeError> {
    let response_size = u32::try_from(response.len()).map_err(|_| OutcomeError::Corrupt)?;
    let capacity = identity
        .handles
        .len()
        .checked_mul(32)
        .and_then(|size| size.checked_add(134))
        .and_then(|size| size.checked_add(response.len()))
        .ok_or(OutcomeError::Corrupt)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(b"RPO1");
    bytes.extend_from_slice(&identity.request_id);
    bytes.extend_from_slice(&identity.batch_id);
    bytes.extend_from_slice(&identity.challenge_hash);
    bytes.extend_from_slice(&identity.csr_hash);
    bytes.push(u8::try_from(identity.handles.len()).map_err(|_| OutcomeError::Identity)?);
    identity
        .handles
        .iter()
        .for_each(|handle| bytes.extend_from_slice(handle));
    bytes.extend_from_slice(&response_size.to_be_bytes());
    bytes.extend_from_slice(digest(&SHA256, response).as_ref());
    bytes.extend_from_slice(response);
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<(AttemptIdentity, Vec<u8>), OutcomeError> {
    let mut cursor = Cursor::new(bytes);
    cursor.exact(b"RPO1")?;
    let request_id = cursor.array()?;
    let batch_id = cursor.array()?;
    let challenge_hash = cursor.array()?;
    let csr_hash = cursor.array()?;
    let count = usize::from(cursor.byte()?);
    let handles = (0..count)
        .map(|_| cursor.array())
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let response_size =
        usize::try_from(u32::from_be_bytes(cursor.array()?)).map_err(|_| OutcomeError::Corrupt)?;
    let expected_hash: [u8; 32] = cursor.array()?;
    let response = cursor.take(response_size)?.to_vec();
    if !cursor.exhausted() || digest(&SHA256, &response).as_ref() != expected_hash {
        return Err(OutcomeError::Corrupt);
    }
    Ok((
        AttemptIdentity::new(
            AttemptIds::new(request_id, batch_id),
            AttemptDigests::new(challenge_hash, csr_hash),
            handles,
        )?,
        response,
    ))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn exact(&mut self, expected: &[u8]) -> Result<(), OutcomeError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(OutcomeError::Corrupt)
        }
    }

    fn byte(&mut self) -> Result<u8, OutcomeError> {
        Ok(*self.take(1)?.first().ok_or(OutcomeError::Corrupt)?)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], OutcomeError> {
        self.take(N)?.try_into().map_err(|_| OutcomeError::Corrupt)
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], OutcomeError> {
        let end = self
            .offset
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(OutcomeError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(OutcomeError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    const fn exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
