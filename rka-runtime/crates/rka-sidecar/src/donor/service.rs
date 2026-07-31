use std::collections::{HashMap, HashSet};

use super::{
    AccessContext, BrokerGenerate, DeleteRequest, DonorBroker, DonorError, DonorKeyState,
    GenerateRequest, PairedPolicy, PublicKeyResult, RemoteKeyHandle, RemoteOperationHandle,
    validation::{authorize, validate_generate},
};

const MAX_KEYS: usize = 4;
const MAX_UPDATES: u16 = 128;
const MAX_TOTAL_INPUT: usize = 1_048_576;
const MAX_CHUNK: usize = 65_536;

#[derive(Debug)]
pub(super) struct KeyRecord {
    pub(super) context: AccessContext,
    pub(super) remote: RemoteKeyHandle,
    public: PublicKeyResult,
    pub(super) state: DonorKeyState,
    pub(super) started_ms: u64,
    pub(super) successful_finishes: u8,
    pub(super) operations: u8,
    pub(super) live: Option<RemoteOperationHandle>,
    pub(super) updates: u16,
    pub(super) total_input: usize,
    pub(super) broker_deleted: bool,
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
    policy: PairedPolicy,
    keys: HashMap<[u8; 16], KeyRecord>,
    request_ids: HashSet<[u8; 16]>,
    nonce_sessions: HashMap<[u8; 32], [u8; 32]>,
}

impl DonorRkaService {
    /// Creates a paired-only service.
    #[must_use]
    pub fn new(policy: PairedPolicy) -> Self {
        Self {
            policy,
            keys: HashMap::new(),
            request_ids: HashSet::new(),
            nonce_sessions: HashMap::new(),
        }
    }

    /// Generates one application key from a fully bound envelope.
    pub fn generate(
        &mut self,
        request: GenerateRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<GenerateResult, DonorError> {
        if self.keys.len() >= MAX_KEYS {
            return Err(DonorError::Capacity);
        }
        self.admit_request(request.request_id)?;
        let validated = validate_generate(self.policy, &request)?;
        if self
            .nonce_sessions
            .get(&request.context.candidate_nonce)
            .is_some_and(|session| session != &request.context.session_id)
        {
            return Err(DonorError::Replay);
        }
        if self.keys.contains_key(&request.alias) {
            return Err(DonorError::Replay);
        }
        let generated = broker
            .generate(BrokerGenerate {
                rkp_handle: request.rkp_handle,
                candidate_aaid: validated.aaid,
                challenge: request.challenge,
                envelope_hash: validated.envelope_hash,
                prior_transcript_hash: request.prior_transcript_hash,
            })
            .map_err(|_| DonorError::Broker)?;
        self.nonce_sessions
            .insert(request.context.candidate_nonce, request.context.session_id);
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

    fn admit_request(&mut self, request_id: [u8; 16]) -> Result<(), DonorError> {
        if !self.request_ids.insert(request_id) {
            return Err(DonorError::Replay);
        }
        Ok(())
    }

    pub(super) fn admit_key_request(&mut self, request: DeleteRequest) -> Result<(), DonorError> {
        let result = (|| {
            authorize(self.policy, request.context)?;
            let record = self
                .keys
                .get(&request.alias)
                .ok_or(DonorError::StaleHandle)?;
            match record.state {
                DonorKeyState::Active => {}
                DonorKeyState::Quarantined => return Err(DonorError::Quarantined),
                DonorKeyState::Deleted => return Err(DonorError::StaleHandle),
            }
            if request.context.session_id != record.context.session_id
                || request.context.candidate_nonce != record.context.candidate_nonce
                || request.context.donor_nonce != record.context.donor_nonce
            {
                return Err(DonorError::IdentityDrift);
            }
            let expires = record
                .started_ms
                .checked_add(rka_protocol::TTL_SECONDS.saturating_mul(1_000))
                .ok_or(DonorError::Expired)?;
            if request.context.now_ms > expires {
                return Err(DonorError::Expired);
            }
            self.admit_request(request.request_id)
        })();
        if result.is_err()
            && let Some(record) = self.keys.get_mut(&request.alias)
        {
            record.state = DonorKeyState::Quarantined;
        }
        result
    }

    pub(super) fn admit_operation(
        &mut self,
        request: &super::OperationRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<(), DonorError> {
        if let Err(error) = self.admit_key_request(DeleteRequest::new(
            request.request_id,
            request.context,
            request.alias,
        )) {
            self.invalidate(request.alias, broker);
            return Err(error);
        }
        if request.input.len() > MAX_CHUNK {
            return Err(DonorError::Capacity);
        }
        let record = self.active_mut(request.alias)?;
        if record.live != Some(request.operation) {
            return Err(DonorError::StaleHandle);
        }
        if record.updates == MAX_UPDATES {
            return Err(DonorError::Capacity);
        }
        let total = record
            .total_input
            .checked_add(request.input.len())
            .ok_or(DonorError::Capacity)?;
        if total > MAX_TOTAL_INPUT {
            return Err(DonorError::Capacity);
        }
        record.updates = record.updates.saturating_add(1);
        record.total_input = total;
        Ok(())
    }

    pub(super) fn active_mut(&mut self, alias: [u8; 16]) -> Result<&mut KeyRecord, DonorError> {
        let record = self.keys.get_mut(&alias).ok_or(DonorError::StaleHandle)?;
        match record.state {
            DonorKeyState::Active => Ok(record),
            DonorKeyState::Quarantined => Err(DonorError::Quarantined),
            DonorKeyState::Deleted => Err(DonorError::StaleHandle),
        }
    }

    pub(super) fn invalidate(&mut self, alias: [u8; 16], broker: &mut impl DonorBroker) {
        let Some(record) = self.keys.get_mut(&alias) else {
            return;
        };
        if record.state == DonorKeyState::Deleted || record.broker_deleted {
            return;
        }
        if let Some(operation) = record.live.take() {
            let _ = broker.abort(operation);
        }
        let _ = broker.delete(record.remote);
        record.broker_deleted = true;
        record.state = DonorKeyState::Quarantined;
    }

    pub(super) fn aliases(&self) -> Vec<[u8; 16]> {
        self.keys.keys().copied().collect()
    }
}
