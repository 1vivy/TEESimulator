use rka_protocol::TTL_SECONDS;

use super::{
    BeginRequest, DeleteRequest, DonorError, DonorKeyState, DonorRkaService, GenerateRequest,
    OperationRequest,
    operations::{MAX_OPERATIONS, MAX_SUCCESSFUL_FINISHES},
    service::{MAX_CHUNK, MAX_KEYS, MAX_TOTAL_INPUT, MAX_UPDATES},
    validation::{authorize, validate_generate},
};

impl DonorRkaService {
    pub(super) fn preflight_generate(
        &self,
        request: &GenerateRequest<'_>,
    ) -> Result<(), DonorError> {
        if self.keys.len() >= MAX_KEYS {
            return Err(DonorError::Capacity);
        }
        if self.request_ids.contains(&request.request_id) {
            return Err(DonorError::Replay);
        }
        validate_generate(self.policy, request)?;
        if self.keys.contains_key(&request.alias) {
            return Err(DonorError::Replay);
        }
        Ok(())
    }

    pub(super) fn preflight_begin(&self, request: BeginRequest) -> Result<(), DonorError> {
        self.preflight_key(request)?;
        let record = self
            .keys
            .get(&request.alias)
            .ok_or(DonorError::StaleHandle)?;
        if record.successful_finishes == MAX_SUCCESSFUL_FINISHES {
            return Err(DonorError::UseLimit);
        }
        if record.live.is_some() {
            return Err(DonorError::ConcurrentOperation);
        }
        if record.operations == MAX_OPERATIONS {
            return Err(DonorError::Capacity);
        }
        Ok(())
    }

    pub(super) fn preflight_operation(
        &self,
        request: &OperationRequest<'_>,
    ) -> Result<(), DonorError> {
        self.preflight_key(DeleteRequest::new(
            request.request_id,
            request.context,
            request.alias,
        ))?;
        if request.input.len() > MAX_CHUNK {
            return Err(DonorError::Capacity);
        }
        let record = self
            .keys
            .get(&request.alias)
            .ok_or(DonorError::StaleHandle)?;
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
        Ok(())
    }

    pub(super) fn preflight_key(&self, request: DeleteRequest) -> Result<(), DonorError> {
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
        if self.request_ids.contains(&request.request_id) {
            return Err(DonorError::Replay);
        }
        Ok(())
    }
}
