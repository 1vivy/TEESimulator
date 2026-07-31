use thiserror::Error;

/// Exact paired candidate policy admitted by one donor runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedPolicy {
    pub(crate) peer_spki_hash: [u8; 32],
    pub(crate) profile_id_hash: [u8; 32],
    pub(crate) profile_epoch: u64,
    pub(crate) candidate_identity_hash: [u8; 32],
    pub(crate) donor_irpc_identity_hash: [u8; 32],
}

impl PairedPolicy {
    #[must_use]
    pub const fn new(
        peer_spki_hash: [u8; 32],
        profile_id_hash: [u8; 32],
        profile_epoch: u64,
        candidate_identity_hash: [u8; 32],
        donor_irpc_identity_hash: [u8; 32],
    ) -> Self {
        Self {
            peer_spki_hash,
            profile_id_hash,
            profile_epoch,
            candidate_identity_hash,
            donor_irpc_identity_hash,
        }
    }
}

/// Authenticated session coordinates supplied by the direct transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessContext {
    pub peer_spki_hash: [u8; 32],
    pub profile_id_hash: [u8; 32],
    pub profile_epoch: u64,
    pub session_id: [u8; 32],
    pub candidate_nonce: [u8; 32],
    pub donor_nonce: [u8; 32],
    pub candidate_identity_hash: [u8; 32],
    pub now_ms: u64,
}

macro_rules! opaque_handle {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $size]);

        impl $name {
            #[must_use]
            pub const fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_array(self) -> [u8; $size] {
                self.0
            }
        }
    };
}

opaque_handle!(RkpKeyHandle, 32);
opaque_handle!(RemoteKeyHandle, 16);
opaque_handle!(RemoteOperationHandle, 16);

/// Correlation and authenticated transport coordinates for one generate.
#[derive(Clone, Copy, Debug)]
pub struct GenerateCoordinates {
    pub request_id: [u8; 16],
    pub context: AccessContext,
    pub alias: [u8; 16],
}

/// Exact public envelope evidence validated before broker exposure.
#[derive(Clone, Copy, Debug)]
pub struct GenerateEvidence<'a> {
    pub candidate_identity: &'a [u8],
    pub authoritative_identity: &'a [u8],
    pub envelope: &'a [u8],
    pub upstream_body: &'a [u8],
    pub ordered_rkp_public_hashes: &'a [[u8; 32]],
    pub phase_hashes: [[u8; 32]; 5],
}

/// Public `KeyMint` inputs selected from one certified RKP lease.
#[derive(Clone, Copy, Debug)]
pub struct GenerateKeyMaterial<'a> {
    pub rkp_handle: RkpKeyHandle,
    pub rkp_chain: &'a [&'a [u8]],
    pub challenge: &'a [u8],
    pub prior_transcript_hash: [u8; 32],
    pub expected_prior_transcript_hash: [u8; 32],
}

/// Complete generate admission input.
#[derive(Clone, Copy, Debug)]
pub struct GenerateRequest<'a> {
    pub(crate) request_id: [u8; 16],
    pub(crate) context: AccessContext,
    pub(crate) alias: [u8; 16],
    pub(crate) candidate_identity: &'a [u8],
    pub(crate) authoritative_identity: &'a [u8],
    pub(crate) envelope: &'a [u8],
    pub(crate) upstream_body: &'a [u8],
    pub(crate) rkp_handle: RkpKeyHandle,
    pub(crate) challenge: &'a [u8],
    pub(crate) prior_transcript_hash: [u8; 32],
    pub(crate) ordered_rkp_public_hashes: &'a [[u8; 32]],
    pub(crate) phase_hashes: [[u8; 32]; 5],
    pub(crate) rkp_chain: &'a [&'a [u8]],
    pub(crate) expected_prior_transcript_hash: [u8; 32],
}

impl<'a> GenerateRequest<'a> {
    pub const fn new(
        coordinates: GenerateCoordinates,
        evidence: GenerateEvidence<'a>,
        key: GenerateKeyMaterial<'a>,
    ) -> Self {
        Self {
            request_id: coordinates.request_id,
            context: coordinates.context,
            alias: coordinates.alias,
            candidate_identity: evidence.candidate_identity,
            authoritative_identity: evidence.authoritative_identity,
            envelope: evidence.envelope,
            upstream_body: evidence.upstream_body,
            rkp_handle: key.rkp_handle,
            challenge: key.challenge,
            prior_transcript_hash: key.prior_transcript_hash,
            ordered_rkp_public_hashes: evidence.ordered_rkp_public_hashes,
            phase_hashes: evidence.phase_hashes,
            rkp_chain: key.rkp_chain,
            expected_prior_transcript_hash: key.expected_prior_transcript_hash,
        }
    }
}

/// Key-scoped request with no payload.
#[derive(Clone, Copy, Debug)]
pub struct DeleteRequest {
    pub(crate) request_id: [u8; 16],
    pub(crate) context: AccessContext,
    pub(crate) alias: [u8; 16],
}

impl DeleteRequest {
    #[must_use]
    pub const fn new(request_id: [u8; 16], context: AccessContext, alias: [u8; 16]) -> Self {
        Self {
            request_id,
            context,
            alias,
        }
    }
}

/// Request to begin the single live operation for an alias.
pub type BeginRequest = DeleteRequest;

/// Operation-scoped request.
#[derive(Clone, Copy, Debug)]
pub struct OperationRequest<'a> {
    pub(crate) request_id: [u8; 16],
    pub(crate) context: AccessContext,
    pub(crate) alias: [u8; 16],
    pub(crate) operation: RemoteOperationHandle,
    pub(crate) input: &'a [u8],
}

impl<'a> OperationRequest<'a> {
    #[must_use]
    pub const fn new(
        request_id: [u8; 16],
        context: AccessContext,
        alias: [u8; 16],
        operation: RemoteOperationHandle,
        input: &'a [u8],
    ) -> Self {
        Self {
            request_id,
            context,
            alias,
            operation,
            input,
        }
    }
}

/// Final operation request.
#[derive(Clone, Copy, Debug)]
pub struct FinishRequest<'a>(pub(crate) OperationRequest<'a>);

impl<'a> FinishRequest<'a> {
    #[must_use]
    pub const fn new(request: OperationRequest<'a>) -> Self {
        Self(request)
    }
}

/// Public alias state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DonorKeyState {
    /// Key may accept one operation.
    Active,
    /// Key was invalidated by a policy or lifecycle failure.
    Quarantined,
    /// Broker key was explicitly deleted.
    Deleted,
}

/// Closed donor policy and lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DonorError {
    #[error("candidate is not paired")]
    Unpaired,
    #[error("profile epoch is stale")]
    StaleProfile,
    #[error("candidate identity drifted")]
    IdentityDrift,
    #[error("request was replayed")]
    Replay,
    #[error("request lifetime expired")]
    Expired,
    #[error("envelope does not bind the request")]
    EnvelopeMismatch,
    #[error("envelope IRPC identity does not match the selected lease")]
    IrpcIdentityMismatch,
    #[error("prior transcript does not match the authenticated frame chain")]
    TranscriptMismatch,
    #[error("module-only envelope reached the upstream body")]
    EnvelopeUpstream,
    #[error("a same-handle operation is already live")]
    ConcurrentOperation,
    #[error("successful use limit is exhausted")]
    UseLimit,
    #[error("requested handle is stale")]
    StaleHandle,
    #[error("broker returned a retained handle")]
    HandleCollision,
    #[error("key is quarantined")]
    Quarantined,
    #[error("bounded capacity was exceeded")]
    Capacity,
    #[error("typed broker operation failed")]
    Broker,
}
