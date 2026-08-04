use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    AccessContext, BrokerGenerate, DeleteRequest, DonorBroker, DonorError, DonorKeyState,
    GenerateRequest, PairedPolicy, PublicKeyResult, RemoteKeyHandle, RemoteOperationHandle,
    quota::{DonorQuota, LiveOperationPermit, MAX_REMOTE_KEYS_PER_CANDIDATE, RemoteKeyPermit},
    validation::validate_generate,
};

pub(super) const MAX_UPDATES: u16 = 128;
pub(super) const MAX_TOTAL_INPUT: usize = 1_048_576;
pub(super) const MAX_CHUNK: usize = 65_536;

#[derive(Debug)]
pub(super) struct KeyRecord {
    pub(super) context: AccessContext,
    pub(super) remote: RemoteKeyHandle,
    pub(super) public: PublicKeyResult,
    pub(super) state: DonorKeyState,
    pub(super) started_ms: u64,
    pub(super) successful_finishes: u8,
    pub(super) operations: u8,
    pub(super) live: Option<RemoteOperationHandle>,
    pub(super) updates: u16,
    pub(super) total_input: usize,
    pub(super) broker_deleted: bool,
    pub(super) live_quota: Option<LiveOperationPermit>,
    pub(super) _key_quota: RemoteKeyPermit,
}

/// Public generate result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerateResult {
    /// State after durable broker generation.
    pub state: DonorKeyState,
}

/// Public begin result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginResult {
    /// Opaque module-owned operation handle.
    pub operation_handle: RemoteOperationHandle,
}

/// Public successful finish result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishResult {
    /// DER ECDSA signature returned by the typed broker.
    pub signature: Vec<u8>,
    /// Count after the successful finish.
    pub successful_finish_count: u8,
}

/// Synchronous donor coordinator. Exclusive mutable access serializes each handle.
#[derive(Debug)]
pub struct DonorRkaService {
    pub(super) policy: PairedPolicy,
    pub(super) keys: HashMap<[u8; 16], KeyRecord>,
    pub(super) request_ids: HashSet<[u8; 16]>,
    pub(super) operation_tombstones: HashSet<RemoteOperationHandle>,
    pub(super) replay_root: Option<PathBuf>,
    pub(super) quota: Arc<DonorQuota>,
}

impl DonorRkaService {
    /// Creates a paired-only service.
    #[must_use]
    pub fn new(policy: PairedPolicy) -> Self {
        Self::with_quota(policy, DonorQuota::shared())
    }

    pub(super) fn with_quota(policy: PairedPolicy, quota: Arc<DonorQuota>) -> Self {
        Self {
            policy,
            keys: HashMap::new(),
            request_ids: HashSet::new(),
            operation_tombstones: HashSet::new(),
            replay_root: None,
            quota,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_durable(policy: PairedPolicy, state_root: &Path) -> Self {
        Self {
            replay_root: Some(state_root.to_path_buf()),
            ..Self::new(policy)
        }
    }

    pub(super) fn new_durable_with_quota(
        policy: PairedPolicy,
        state_root: &Path,
        quota: Arc<DonorQuota>,
    ) -> Self {
        Self {
            replay_root: Some(state_root.to_path_buf()),
            ..Self::with_quota(policy, quota)
        }
    }

    /// Generates one application key from a fully bound envelope.
    pub fn generate(
        &mut self,
        request: GenerateRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<GenerateResult, DonorError> {
        if self.keys.len() >= MAX_REMOTE_KEYS_PER_CANDIDATE {
            return Err(DonorError::Capacity);
        }
        self.admit_request(request.request_id)?;
        let validated = validate_generate(self.policy, &request)?;
        if self.keys.contains_key(&request.alias) {
            return Err(DonorError::Replay);
        }
        let key_quota = self.quota.acquire_remote_key()?;
        let generated = broker
            .generate(BrokerGenerate {
                alias: request.alias,
                rkp_handle: request.rkp_handle,
                rkp_chain: request.rkp_chain,
                candidate_aaid: validated.aaid,
                challenge: request.challenge,
                envelope_hash: validated.envelope_hash,
                prior_transcript_hash: request.prior_transcript_hash,
            })
            .map_err(|_| DonorError::Broker)?;
        self.keys.insert(
            request.alias,
            KeyRecord {
                context: request.context,
                remote: generated.handle,
                public: generated,
                state: DonorKeyState::Active,
                started_ms: validated.started_ms,
                successful_finishes: 0,
                operations: 0,
                live: None,
                updates: 0,
                total_input: 0,
                broker_deleted: false,
                live_quota: None,
                _key_quota: key_quota,
            },
        );
        Ok(GenerateResult {
            state: DonorKeyState::Active,
        })
    }

    /// Returns the retained public key only after exact authorization.
    pub fn get(&mut self, request: DeleteRequest) -> Result<&PublicKeyResult, DonorError> {
        self.admit_key_request(request)?;
        let record = self
            .keys
            .get(&request.alias)
            .ok_or(DonorError::StaleHandle)?;
        match record.state {
            DonorKeyState::Active => Ok(&record.public),
            DonorKeyState::Quarantined => Err(DonorError::Quarantined),
            DonorKeyState::Deleted => Err(DonorError::StaleHandle),
        }
    }

    /// Returns a redacted alias state without exposing broker material.
    #[must_use]
    pub fn key_state(&self, alias: [u8; 16]) -> Option<DonorKeyState> {
        self.keys.get(&alias).map(|record| record.state)
    }
}
