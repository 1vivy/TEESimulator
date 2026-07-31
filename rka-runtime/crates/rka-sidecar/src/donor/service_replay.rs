use rka_protocol::{OperationHandle, PeerSpkiHash, SessionId, operation_tombstone};
use rka_state::{ReplayManager, StateError, TombstoneTime};

use super::{AccessContext, DonorError, DonorRkaService, RemoteOperationHandle};
use crate::provisioning_io::FileStateStore;

impl DonorRkaService {
    pub(super) fn retain_operation(&mut self, operation: RemoteOperationHandle) -> bool {
        self.operation_tombstones.insert(operation)
    }

    pub(super) fn operation_retained(&self, operation: RemoteOperationHandle) -> bool {
        self.operation_tombstones.contains(&operation)
    }

    pub(super) fn operation_owner(&self, operation: RemoteOperationHandle) -> Option<[u8; 16]> {
        self.keys
            .iter()
            .find_map(|(alias, record)| (record.live == Some(operation)).then_some(*alias))
    }

    pub(super) fn public_for_alias(&self, alias: [u8; 16]) -> Option<&super::PublicKeyResult> {
        self.keys.get(&alias).map(|record| &record.public)
    }

    pub(super) fn persist_operation(
        &mut self,
        context: AccessContext,
        operation: RemoteOperationHandle,
    ) -> Result<(), DonorError> {
        let Some(root) = self.replay_root.as_deref() else {
            self.operation_tombstones.insert(operation);
            return Ok(());
        };
        let store = FileStateStore::new(root);
        let mut replay = ReplayManager::load(&store).map_err(|_| DonorError::Storage)?;
        let key = operation_tombstone(
            (
                PeerSpkiHash::new(context.peer_spki_hash),
                context.profile_epoch,
                SessionId::new(context.session_id),
            ),
            OperationHandle::new(operation.as_array()),
        );
        replay
            .persist(
                &key,
                TombstoneTime::new(context.now_ms / 1_000, context.profile_epoch),
            )
            .map_err(map_state_error)?;
        self.operation_tombstones.insert(operation);
        Ok(())
    }
}

const fn map_state_error(error: StateError) -> DonorError {
    match error {
        StateError::Replay => DonorError::HandleCollision,
        _ => DonorError::Storage,
    }
}
