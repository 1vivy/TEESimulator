use super::{DonorBroker, DonorKeyState, RemoteKeyHandle, service::DonorRkaService};

impl DonorRkaService {
    pub(super) fn reject_key_collision(
        &mut self,
        handle: RemoteKeyHandle,
        broker: &mut impl DonorBroker,
    ) {
        let owner = self
            .keys
            .iter()
            .find_map(|(alias, record)| (record.remote == handle).then_some(*alias));
        if let Some(alias) = owner {
            if let Some(operation) = self
                .keys
                .get_mut(&alias)
                .and_then(|record| record.live.take())
            {
                self.operation_tombstones.insert(operation);
                let _ = broker.abort(operation);
            }
            if let Some(record) = self.keys.get_mut(&alias)
                && record.state != DonorKeyState::Deleted
            {
                record.state = DonorKeyState::Quarantined;
                record.broker_deleted = true;
            }
        }
        let _ = broker.delete(handle);
    }
}
