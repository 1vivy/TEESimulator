use std::fmt;

use super::BridgeError;

pub(super) const MAGIC: [u8; 4] = *b"RKB1";
pub(super) const VERSION: u8 = 1;
pub(super) const HEADER_BYTES: usize = 24;
pub(super) const MAX_FRAME_BYTES: usize = 1_048_576;
pub(super) const MAX_UPDATE_BYTES: usize = 65_536;
pub(super) const MAX_TOTAL_INPUT_BYTES: usize = 1_048_576;
pub(super) const MAX_CERTIFICATE_BYTES: usize = 65_536;
pub(super) const MAX_CHAIN_BYTES: usize = 524_288;
pub(super) const MAX_CHAIN_CERTIFICATES: usize = 20;
pub(super) const MAX_PUBLIC_KEYS: usize = 20;

#[doc = "Request correlation identifier."]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(u64);

impl RequestId {
    #[doc = "Creates a request identifier."]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[doc = "Returns the wire value."]
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[doc = "Owned public bytes wiped when released."]
#[derive(Eq, PartialEq)]
pub struct PublicBytes(Vec<u8>);

impl PublicBytes {
    #[doc = "Defensively copies bytes after enforcing fixed bounds."]
    pub fn bounded(bytes: &[u8], minimum: usize, maximum: usize) -> Result<Self, BridgeError> {
        if bytes.len() < minimum || bytes.len() > maximum {
            return Err(BridgeError::ValueTooLarge);
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(bytes.len())
            .map_err(|_| BridgeError::Allocation)?;
        value.extend_from_slice(bytes);
        Ok(Self(value))
    }

    #[doc = "Borrows the public bytes."]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PublicBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicBytes")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl Drop for PublicBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

macro_rules! fixed_bytes {
    ($name:ident, $size:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Eq, PartialEq)]
        pub struct $name([u8; $size]);
        impl $name {
            #[doc = "Creates the fixed-width value."]
            pub const fn new(value: [u8; $size]) -> Self {
                Self(value)
            }
            #[doc = "Borrows the fixed-width bytes."]
            pub const fn as_array(&self) -> &[u8; $size] {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(redacted)"))
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                self.0.fill(0);
            }
        }
    };
}

fixed_bytes!(Hash32, 32, "Redacted fixed-width public hash.");
fixed_bytes!(NetworkHandle, 16, "Opaque network-only operation handle.");

/// Exact broker-journal identity for one ordered generated key.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerKeyMetadata {
    order: u8,
    handle: Hash32,
    public_key_hash: Hash32,
    spki_hash: Hash32,
}

impl BrokerKeyMetadata {
    /// Creates one bounded ordered broker identity.
    #[allow(
        clippy::too_many_arguments,
        reason = "one ordered key binds three independent broker identities"
    )]
    pub fn new(
        order: u8,
        handle: [u8; 32],
        public_key_hash: [u8; 32],
        spki_hash: [u8; 32],
    ) -> Result<Self, BridgeError> {
        if usize::from(order) >= MAX_PUBLIC_KEYS {
            return Err(BridgeError::NonCanonical);
        }
        Ok(Self {
            order,
            handle: Hash32::new(handle),
            public_key_hash: Hash32::new(public_key_hash),
            spki_hash: Hash32::new(spki_hash),
        })
    }

    /// Returns the broker-journal order.
    pub const fn order(&self) -> u8 {
        self.order
    }

    /// Returns the exact opaque broker handle.
    pub const fn handle(&self) -> &[u8; 32] {
        self.handle.as_array()
    }

    /// Returns the MACed-public-key hash.
    pub const fn public_key_hash(&self) -> &[u8; 32] {
        self.public_key_hash.as_array()
    }

    /// Returns the SPKI hash.
    pub const fn spki_hash(&self) -> &[u8; 32] {
        self.spki_hash.as_array()
    }
}

#[doc = "One closed, public-only bridge DTO."]
#[derive(Eq, PartialEq)]
#[non_exhaustive]
pub enum BridgeMessage {
    #[doc = "Requests public CSR material."]
    PublicKeyRequest(RequestId, PublicBytes, u8),
    #[doc = "Returns public CSR and exact ordered broker identities."]
    PublicKeyResponse(RequestId, PublicBytes, Vec<BrokerKeyMetadata>),
    #[doc = "Supplies a bounded operation chunk."]
    UpdateRequest(RequestId, NetworkHandle, PublicBytes, u32),
    #[doc = "Returns a public SPKI and DER chain."]
    PublicResult(RequestId, NetworkHandle, PublicBytes, Vec<PublicBytes>),
    #[doc = "Cancels one correlated request."]
    Cancel(RequestId, Vec<Hash32>),
    #[doc = "Returns one redacted typed failure."]
    Error(RequestId, u8, Hash32),
}

impl BridgeMessage {
    #[doc = "Returns the correlation identifier."]
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::PublicKeyRequest(id, ..)
            | Self::PublicKeyResponse(id, ..)
            | Self::UpdateRequest(id, ..)
            | Self::PublicResult(id, ..)
            | Self::Cancel(id, ..)
            | Self::Error(id, ..) => *id,
        }
    }

    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::PublicKeyRequest(..) => 1,
            Self::PublicKeyResponse(..) => 2,
            Self::UpdateRequest(..) => 3,
            Self::PublicResult(..) => 4,
            Self::Cancel(..) => 5,
            Self::Error(..) => 6,
        }
    }
}

impl fmt::Debug for BridgeMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeMessage")
            .field("request_id", &self.request_id())
            .field("tag", &self.tag())
            .finish_non_exhaustive()
    }
}

#[doc = "Direction and allowed tags for one exchange side."]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExchangeRole {
    #[doc = "Sidecar sends a donor request."]
    DonorRequest,
    #[doc = "Broker sends a donor response."]
    DonorResponse,
    #[doc = "Broker sends a candidate request."]
    CandidateRequest,
    #[doc = "Sidecar sends a candidate response."]
    CandidateResponse,
}

impl ExchangeRole {
    pub(crate) const fn direction(self) -> u8 {
        match self {
            Self::DonorRequest | Self::CandidateResponse => 1,
            Self::DonorResponse | Self::CandidateRequest => 2,
        }
    }

    pub(crate) const fn accepts(self, tag: u8) -> bool {
        match self {
            Self::DonorRequest | Self::CandidateRequest => matches!(tag, 1 | 3 | 5),
            Self::DonorResponse | Self::CandidateResponse => matches!(tag, 2 | 4 | 5 | 6),
        }
    }
}

#[doc = "Returns the one response tag accepted for a request."]
pub const fn expected_response_tag(message: &BridgeMessage) -> Result<u8, BridgeError> {
    match message {
        BridgeMessage::PublicKeyRequest(..) => Ok(2),
        BridgeMessage::UpdateRequest(..) => Ok(4),
        BridgeMessage::Cancel(..) => Ok(5),
        BridgeMessage::PublicKeyResponse(..)
        | BridgeMessage::PublicResult(..)
        | BridgeMessage::Error(..) => Err(BridgeError::UnexpectedTag),
    }
}

#[doc = "Request, response-kind, and reconnect-generation correlation."]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Correlation {
    request_id: RequestId,
    expected_tag: u8,
    generation: u64,
}

impl Correlation {
    #[doc = "Creates correlation from a request and current generation."]
    pub const fn new(message: &BridgeMessage, generation: u64) -> Result<Self, BridgeError> {
        let expected_tag = match expected_response_tag(message) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Ok(Self {
            request_id: message.request_id(),
            expected_tag,
            generation,
        })
    }

    #[doc = "Accepts only exact identifier, kind, and generation."]
    pub const fn accepts(&self, message: &BridgeMessage, generation: u64) -> bool {
        self.generation == generation
            && self.request_id.value() == message.request_id().value()
            && (self.expected_tag == message.tag() || matches!(message, BridgeMessage::Error(..)))
    }
}
