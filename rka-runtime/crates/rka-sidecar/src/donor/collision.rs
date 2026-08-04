use std::collections::{HashMap, hash_map::Entry};

use crate::candidate::{AuthenticatedCandidateContext, CandidateId};

use super::{DonorBroker, DonorError, DonorSupervisor, RemoteKeyHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemoteKeyOwner {
    candidate: CandidateId,
    alias: [u8; 16],
}

#[derive(Debug, Default)]
pub(super) struct RemoteKeyRegistry {
    owners: HashMap<RemoteKeyHandle, RemoteKeyOwner>,
}

impl RemoteKeyRegistry {
    fn register(
        &mut self,
        handle: RemoteKeyHandle,
        owner: RemoteKeyOwner,
    ) -> Result<(), RemoteKeyOwner> {
        match self.owners.entry(handle) {
            Entry::Occupied(entry) => Err(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(owner);
                Ok(())
            }
        }
    }
}

impl<B: DonorBroker> DonorSupervisor<B> {
    pub(super) fn register_generated_key(
        &mut self,
        context: &AuthenticatedCandidateContext,
        alias: [u8; 16],
    ) -> Result<(), DonorError> {
        let handle = self
            .shard(context)?
            .service
            .remote_for_alias(alias)
            .ok_or(DonorError::Broker)?;
        let current = RemoteKeyOwner {
            candidate: *context.candidate(),
            alias,
        };
        let Err(existing) = self.remote_keys.register(handle, current) else {
            return Ok(());
        };
        {
            let (shards, broker) = (&mut self.shards, &mut self.broker);
            if let Some(shard) = shards.get_mut(&existing.candidate) {
                shard.service.invalidate(existing.alias, broker);
            }
        }
        {
            let (shards, broker) = (&mut self.shards, &mut self.broker);
            if let Some(shard) = shards.get_mut(&current.candidate) {
                shard
                    .service
                    .quarantine_after_remote_delete(current.alias, broker);
            }
        }
        Err(DonorError::HandleCollision)
    }
}
