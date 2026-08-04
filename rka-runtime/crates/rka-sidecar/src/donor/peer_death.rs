use super::{DonorBroker, DonorKeyState, DonorRkaService};

impl DonorRkaService {
    pub(super) fn invalidate_after_candidate_death(&mut self, broker: &mut impl DonorBroker) {
        for alias in self.aliases() {
            let Some(record) = self.keys.get_mut(&alias) else {
                continue;
            };
            if record.state == DonorKeyState::Deleted || record.broker_deleted {
                continue;
            }
            if let Some(operation) = record.live.take() {
                drop(record.live_quota.take());
                self.operation_tombstones.insert(operation);
                let _ = broker.enqueue_abort(operation);
            }
            let _ = broker.enqueue_delete(record.remote);
            record.broker_deleted = true;
            record.state = DonorKeyState::Quarantined;
        }
    }

    pub(super) fn invalidate_after_broker_death(&mut self) {
        for record in self.keys.values_mut() {
            if let Some(operation) = record.live.take() {
                drop(record.live_quota.take());
                self.operation_tombstones.insert(operation);
            }
            if record.state != DonorKeyState::Deleted {
                record.broker_deleted = true;
                record.state = DonorKeyState::Quarantined;
            }
        }
    }
}
