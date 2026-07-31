use thiserror::Error;

/// Exact paired candidate policy admitted by one donor runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedPolicy {
    pub(crate) peer_spki_hash: [u8; 32],
    pub(crate) profile_id_hash: [u8; 32],
    pub(crate) profile_epoch: u64,
    pub(crate) candidate_identity_hash: [u8; 32],
}

impl PairedPolicy {
    #[must_use]
    pub const fn new(
        peer_spki_hash: [u8; 32],
        profile_id_hash: [u8; 32],
        profile_epoch: u64,
        candidate_identity_hash: [u8; 32],
    ) -> Self {
        Self {
            peer_spki_hash,
            profile_id_hash,
            profile_epoch,
            candidate_identity_hash,
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
        }
    };
}

opaque_handle!(RemoteKeyHandle, 32);
opaque_handle!(RemoteOperationHandle, 16);

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
    pub(crate) rkp_handle: RemoteKeyHandle,
    pub(crate) challenge: &'a [u8],
    pub(crate) prior_transcript_hash: [u8; 32],
    pub(crate) ordered_rkp_public_hashes: &'a [[u8; 32]],
    pub(crate) phase_hashes: [[u8; 32]; 5],
}

impl<'a> GenerateRequest<'a> {
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds every independent envelope phase at one trust boundary"
    )]
    pub const fn new(
        request_id: [u8; 16],
        context: AccessContext,
        alias: [u8; 16],
        candidate_identity: &'a [u8],
        authoritative_identity: &'a [u8],
        envelope: &'a [u8],
        upstream_body: &'a [u8],
        rkp_handle: RemoteKeyHandle,
        challenge: &'a [u8],
        prior_transcript_hash: [u8; 32],
        ordered_rkp_public_hashes: &'a [[u8; 32]],
        hal_csr_hash: [u8; 32],
        server_body_hash: [u8; 32],
        server_challenge_hash: [u8; 32],
        server_response_hash: [u8; 32],
        chain_set_hash: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            context,
            alias,
            candidate_identity,
            authoritative_identity,
            envelope,
            upstream_body,
            rkp_handle,
            challenge,
            prior_transcript_hash,
            ordered_rkp_public_hashes,
            phase_hashes: [
                hal_csr_hash,
                server_body_hash,
                server_challenge_hash,
                server_response_hash,
                chain_set_hash,
            ],
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
    #[error("module-only envelope reached the upstream body")]
    EnvelopeUpstream,
    #[error("a same-handle operation is already live")]
    ConcurrentOperation,
    #[error("successful use limit is exhausted")]
    UseLimit,
    #[error("requested handle is stale")]
    StaleHandle,
    #[error("key is quarantined")]
    Quarantined,
    #[error("bounded capacity was exceeded")]
    Capacity,
    #[error("typed broker operation failed")]
    Broker,
}
