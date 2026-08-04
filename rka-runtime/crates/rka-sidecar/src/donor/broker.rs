use super::{RemoteKeyHandle, RemoteOperationHandle, RkpKeyHandle};
use crate::candidate::CandidateId;

/// Broker generate request containing public inputs and typed handles only.
#[derive(Clone, Copy, Debug)]
pub struct BrokerGenerate<'a> {
    pub alias: [u8; 16],
    pub rkp_handle: RkpKeyHandle,
    pub rkp_chain: &'a [&'a [u8]],
    pub candidate_aaid: &'a [u8],
    pub challenge: &'a [u8],
    pub envelope_hash: [u8; 32],
    pub prior_transcript_hash: [u8; 32],
}

/// Typed begin request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerBegin {
    pub key_handle: RemoteKeyHandle,
}

/// Public generated-key result. No key blob or live broker object crosses this seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedKey {
    pub handle: RemoteKeyHandle,
    pub certificate_chain: Vec<Vec<u8>>,
    pub leaf_spki_hash: [u8; 32],
    pub characteristics_hash: [u8; 32],
    pub transcript_signature: Vec<u8>,
}

impl GeneratedKey {
    #[must_use]
    pub fn new(
        handle: RemoteKeyHandle,
        certificate_chain: Vec<Vec<u8>>,
        leaf_spki_hash: [u8; 32],
        characteristics_hash: [u8; 32],
    ) -> Self {
        Self {
            handle,
            certificate_chain,
            leaf_spki_hash,
            characteristics_hash,
            transcript_signature: vec![1],
        }
    }

    pub(crate) fn with_transcript_signature(mut self, signature: Vec<u8>) -> Self {
        self.transcript_signature = signature;
        self
    }
}

/// Public key response retained by the donor.
pub type PublicKeyResult = GeneratedKey;

/// Redacted broker failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerFailure {
    Unavailable,
    Rejected,
}

/// Typed Android broker boundary.
pub trait DonorBroker {
    fn bind_candidate(&mut self, candidate: &CandidateId);
    fn generate(&mut self, request: BrokerGenerate<'_>) -> Result<GeneratedKey, BrokerFailure>;
    fn begin(&mut self, request: BrokerBegin) -> Result<RemoteOperationHandle, BrokerFailure>;
    fn update_aad(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<usize, BrokerFailure>;
    fn update(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure>;
    fn finish(
        &mut self,
        operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure>;
    fn abort(&mut self, operation: RemoteOperationHandle) -> Result<(), BrokerFailure>;
    fn delete(&mut self, key: RemoteKeyHandle) -> Result<(), BrokerFailure>;
    fn get(&mut self, key: RemoteKeyHandle) -> Result<PublicKeyResult, BrokerFailure>;
}
