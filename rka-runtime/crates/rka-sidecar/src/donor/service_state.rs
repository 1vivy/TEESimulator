use rka_protocol::TTL_SECONDS;

use super::{
    DeleteRequest, DonorBroker, DonorError, DonorKeyState, DonorRkaService, OperationRequest,
    RemoteKeyHandle, validation::authorize,
};

use super::service::{MAX_CHUNK, MAX_TOTAL_INPUT, MAX_UPDATES};

impl DonorRkaService {
    pub(super) fn admit_request(&mut self, request_id: [u8; 16]) -> Result<(), DonorError> {
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
                .checked_add(TTL_SECONDS.saturating_mul(1_000))
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
        request: &OperationRequest<'_>,
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
            self.invalidate(request.alias, broker);
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

    pub(super) fn active_mut(
        &mut self,
        alias: [u8; 16],
    ) -> Result<&mut super::service::KeyRecord, DonorError> {
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
            drop(record.live_quota.take());
            let _ = broker.abort(operation);
            self.operation_tombstones.insert(operation);
        }
        let _ = broker.delete(record.remote);
        record.broker_deleted = true;
        record.state = DonorKeyState::Quarantined;
    }

    pub(super) fn aliases(&self) -> Vec<[u8; 16]> {
        self.keys.keys().copied().collect()
    }

    pub(super) fn has_live_operation(&self) -> bool {
        self.keys.values().any(|record| record.live.is_some())
    }

    pub(super) fn remote_for_alias(&self, alias: [u8; 16]) -> Option<RemoteKeyHandle> {
        self.keys.get(&alias).map(|record| record.remote)
    }

    pub(super) fn quarantine_after_remote_delete(
        &mut self,
        alias: [u8; 16],
        broker: &mut impl DonorBroker,
    ) {
        let Some(record) = self.keys.get_mut(&alias) else {
            return;
        };
        if let Some(operation) = record.live.take() {
            drop(record.live_quota.take());
            let _ = broker.abort(operation);
            self.operation_tombstones.insert(operation);
        }
        record.broker_deleted = true;
        record.state = DonorKeyState::Quarantined;
    }
}
