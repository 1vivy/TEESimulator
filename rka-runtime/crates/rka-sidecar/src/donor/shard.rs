use std::{collections::HashMap, path::PathBuf};

use crate::candidate::{AuthenticatedCandidateContext, CandidateId, PairingCatalog};

use super::{
    DonorBroker, DonorError, DonorRkaService, PairedPolicy, collision::RemoteKeyRegistry,
    runtime::RuntimeTrust, state::TranscriptJournal,
};

/// All donor state owned by one authenticated candidate.
#[derive(Debug)]
pub struct CandidateShard {
    pub(super) id: CandidateId,
    pub(super) service: DonorRkaService,
    pub(super) transcript: Option<TranscriptJournal>,
    pub(super) replay_root: Option<PathBuf>,
    pub(super) pair: PairedPolicy,
    pub(super) trust: Option<RuntimeTrust>,
}

pub(super) struct DurableShardState {
    pub(super) trust: RuntimeTrust,
    pub(super) replay_root: PathBuf,
    pub(super) transcript: TranscriptJournal,
}

impl CandidateShard {
    /// Returns the catalog-authenticated candidate identity.
    #[must_use]
    pub const fn candidate(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the policy bound to this candidate shard.
    #[must_use]
    pub const fn policy(&self) -> PairedPolicy {
        self.pair
    }

    pub(super) fn in_memory(
        context: &AuthenticatedCandidateContext,
        pair: PairedPolicy,
    ) -> Result<Self, DonorError> {
        validate_pair(context, pair)?;
        Ok(Self {
            id: *context.candidate(),
            service: DonorRkaService::new(pair),
            transcript: None,
            replay_root: None,
            pair,
            trust: None,
        })
    }

    pub(super) fn durable(
        context: &AuthenticatedCandidateContext,
        pair: PairedPolicy,
        state: DurableShardState,
    ) -> Result<Self, DonorError> {
        validate_pair(context, pair)?;
        Ok(Self {
            id: *context.candidate(),
            service: DonorRkaService::new_durable(pair, &state.replay_root),
            transcript: Some(state.transcript),
            replay_root: Some(state.replay_root),
            pair,
            trust: Some(state.trust),
        })
    }

    pub(super) fn operation_owner(
        &self,
        operation: super::RemoteOperationHandle,
    ) -> Option<[u8; 16]> {
        self.service.operation_owner(operation)
    }
}

/// Synchronous donor-wide owner of authenticated candidate shards.
#[derive(Debug)]
pub struct DonorSupervisor<B: DonorBroker> {
    pub(super) shards: HashMap<CandidateId, CandidateShard>,
    pub(super) broker: B,
    pub(super) catalog: PairingCatalog,
    pub(super) remote_keys: RemoteKeyRegistry,
    pub(super) state_root: Option<PathBuf>,
    pub(super) local_candidate: Option<AuthenticatedCandidateContext>,
}

impl<B: DonorBroker> DonorSupervisor<B> {
    /// Creates a supervisor over an already trusted pairing catalog.
    #[must_use]
    pub fn with_broker(catalog: PairingCatalog, broker: B) -> Self {
        Self {
            shards: HashMap::new(),
            broker,
            catalog,
            remote_keys: RemoteKeyRegistry::default(),
            state_root: None,
            local_candidate: None,
        }
    }

    /// Activates one in-memory shard from catalog-authenticated coordinates.
    pub fn activate_candidate(
        &mut self,
        context: &AuthenticatedCandidateContext,
        pair: PairedPolicy,
    ) -> Result<(), DonorError> {
        self.authenticate(context)?;
        if self.shards.contains_key(context.candidate()) {
            return Err(DonorError::Replay);
        }
        let shard = CandidateShard::in_memory(context, pair)?;
        self.shards.insert(*context.candidate(), shard);
        Ok(())
    }

    pub(super) fn shard(
        &self,
        context: &AuthenticatedCandidateContext,
    ) -> Result<&CandidateShard, DonorError> {
        self.shards
            .get(context.candidate())
            .ok_or(DonorError::Unpaired)
    }

    pub(super) fn shard_mut(
        &mut self,
        context: &AuthenticatedCandidateContext,
    ) -> Result<&mut CandidateShard, DonorError> {
        shard_mut(&mut self.shards, context)
    }

    pub(super) fn ensure_candidate(
        &mut self,
        context: &AuthenticatedCandidateContext,
    ) -> Result<(), DonorError> {
        self.authenticate(context)?;
        if !self.shards.contains_key(context.candidate()) {
            let root = self.state_root.as_deref().ok_or(DonorError::Unpaired)?;
            let shard = super::runtime::load_candidate(root, context)?;
            self.shards.insert(*context.candidate(), shard);
        }
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        context: &AuthenticatedCandidateContext,
    ) -> Result<(), DonorError> {
        let admitted = self
            .catalog
            .lookup(
                *context.peer_spki_hash(),
                *context.profile_id_hash(),
                context.profile_epoch(),
            )
            .map_err(|_| DonorError::Unpaired)?;
        if admitted.candidate() != context.candidate() {
            return Err(DonorError::Unpaired);
        }
        Ok(())
    }
}

pub(super) fn shard_mut<'a>(
    shards: &'a mut HashMap<CandidateId, CandidateShard>,
    context: &AuthenticatedCandidateContext,
) -> Result<&'a mut CandidateShard, DonorError> {
    shards
        .get_mut(context.candidate())
        .ok_or(DonorError::Unpaired)
}

fn validate_pair(
    context: &AuthenticatedCandidateContext,
    pair: PairedPolicy,
) -> Result<(), DonorError> {
    if pair.peer_spki_hash != *context.peer_spki_hash()
        || pair.profile_id_hash != *context.profile_id_hash()
        || pair.candidate_identity_hash != *context.candidate().as_bytes()
    {
        return Err(DonorError::Unpaired);
    }
    if pair.profile_epoch != context.profile_epoch() {
        return Err(DonorError::StaleProfile);
    }
    Ok(())
}
