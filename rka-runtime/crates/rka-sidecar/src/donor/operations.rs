use super::{
    BeginRequest, BrokerBegin, DeleteRequest, DonorBroker, DonorError, DonorKeyState,
    FinishRequest, OperationRequest,
    service::{BeginResult, DonorRkaService, FinishResult},
};

pub(super) const MAX_OPERATIONS: u8 = 4;
pub(super) const MAX_SUCCESSFUL_FINISHES: u8 = 1;

impl DonorRkaService {
    pub fn begin(
        &mut self,
        request: BeginRequest,
        broker: &mut impl DonorBroker,
    ) -> Result<BeginResult, DonorError> {
        if let Err(error) = self.admit_key_request(request) {
            self.invalidate(request.alias, broker);
            return Err(error);
        }
        let record = self.active_mut(request.alias)?;
        if record.successful_finishes == MAX_SUCCESSFUL_FINISHES {
            return Err(DonorError::UseLimit);
        }
        if record.live.is_some() {
            return Err(DonorError::ConcurrentOperation);
        }
        if record.operations == MAX_OPERATIONS {
            return Err(DonorError::Capacity);
        }
        let Ok(operation) = broker.begin(BrokerBegin {
            key_handle: record.remote,
        }) else {
            self.invalidate(request.alias, broker);
            return Err(DonorError::Broker);
        };
        if self.operation_retained(operation) {
            if let Some(owner) = self.operation_owner(operation) {
                self.invalidate(owner, broker);
            } else {
                let _ = broker.abort(operation);
            }
            self.invalidate(request.alias, broker);
            return Err(DonorError::HandleCollision);
        }
        if let Some(owner) = self.operation_owner(operation) {
            self.retain_operation(operation);
            self.invalidate(owner, broker);
            self.invalidate(request.alias, broker);
            return Err(DonorError::HandleCollision);
        }
        if let Err(error) = self.persist_operation(request.context, operation) {
            let _ = broker.abort(operation);
            self.invalidate(request.alias, broker);
            return Err(error);
        }
        let record = self.active_mut(request.alias)?;
        record.operations = record.operations.saturating_add(1);
        record.live = Some(operation);
        record.updates = 0;
        record.total_input = 0;
        Ok(BeginResult {
            operation_handle: operation,
        })
    }

    pub fn update_aad(
        &mut self,
        request: OperationRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<usize, DonorError> {
        self.admit_operation(&request, broker)?;
        let Ok(consumed) = broker.update_aad(request.operation, request.input) else {
            self.invalidate(request.alias, broker);
            return Err(DonorError::Broker);
        };
        Ok(consumed)
    }

    pub fn update(
        &mut self,
        request: OperationRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<Vec<u8>, DonorError> {
        self.admit_operation(&request, broker)?;
        let Ok(output) = broker.update(request.operation, request.input) else {
            self.invalidate(request.alias, broker);
            return Err(DonorError::Broker);
        };
        Ok(output)
    }

    pub fn finish(
        &mut self,
        request: FinishRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<FinishResult, DonorError> {
        self.admit_operation(&request.0, broker)?;
        let Ok(signature) = broker.finish(request.0.operation, request.0.input) else {
            self.invalidate(request.0.alias, broker);
            return Err(DonorError::Broker);
        };
        let record = self.active_mut(request.0.alias)?;
        record.live = None;
        record.successful_finishes = record.successful_finishes.saturating_add(1);
        Ok(FinishResult {
            signature,
            successful_finish_count: record.successful_finishes,
        })
    }

    pub fn abort(
        &mut self,
        request: OperationRequest<'_>,
        broker: &mut impl DonorBroker,
    ) -> Result<(), DonorError> {
        self.admit_operation(&request, broker)?;
        if broker.abort(request.operation).is_err() {
            self.invalidate(request.alias, broker);
            return Err(DonorError::Broker);
        }
        self.active_mut(request.alias)?.live = None;
        Ok(())
    }

    pub fn delete(
        &mut self,
        request: DeleteRequest,
        broker: &mut impl DonorBroker,
    ) -> Result<DonorKeyState, DonorError> {
        self.admit_key_request(request)?;
        let record = self.active_mut(request.alias)?;
        if let Some(operation) = record.live {
            self.retain_operation(operation);
            if broker.abort(operation).is_err() {
                self.invalidate(request.alias, broker);
                return Err(DonorError::Broker);
            }
            self.active_mut(request.alias)?.live = None;
        }
        let remote = self.active_mut(request.alias)?.remote;
        if broker.delete(remote).is_err() {
            self.invalidate(request.alias, broker);
            return Err(DonorError::Broker);
        }
        let record = self.active_mut(request.alias)?;
        record.broker_deleted = true;
        record.state = DonorKeyState::Deleted;
        Ok(record.state)
    }

    pub(super) fn invalidate_all(&mut self, broker: &mut impl DonorBroker) {
        let aliases = self.aliases();
        for alias in aliases {
            self.invalidate(alias, broker);
        }
    }
}
