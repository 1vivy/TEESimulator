use std::path::Path;

use super::{
    BeginRequest, BeginResult, BridgeDonorBroker, DeleteRequest, DonorError, DonorKeyState,
    DonorRkaService, FinishRequest, FinishResult, GenerateRequest, GenerateResult,
    OperationRequest, PairedPolicy, PublicKeyResult,
};

/// Production donor lifecycle wired to the authenticated Android broker bridge.
#[derive(Debug)]
pub struct DonorRuntime {
    service: Option<DonorRkaService>,
    broker: BridgeDonorBroker,
}

impl DonorRuntime {
    /// Creates a dormant donor role without accepting unpaired requests.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            service: None,
            broker: BridgeDonorBroker::new(socket),
        }
    }

    /// Activates the exact paired policy supplied by authenticated orchestration.
    pub fn activate(&mut self, policy: PairedPolicy) {
        self.service = Some(DonorRkaService::new(policy));
    }

    /// Generates one retained application key through the typed broker bridge.
    pub fn generate(&mut self, request: GenerateRequest<'_>) -> Result<GenerateResult, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.generate(request, &mut self.broker)
    }

    /// Returns retained public material after exact key authorization.
    pub fn get(&mut self, request: DeleteRequest) -> Result<&PublicKeyResult, DonorError> {
        self.service
            .as_mut()
            .ok_or(DonorError::Unpaired)?
            .get(request)
    }

    /// Begins the sole live operation for a retained key.
    pub fn begin(&mut self, request: BeginRequest) -> Result<BeginResult, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.begin(request, &mut self.broker)
    }

    /// Sends authenticated associated data to the live operation.
    pub fn update_aad(&mut self, request: OperationRequest<'_>) -> Result<usize, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.update_aad(request, &mut self.broker)
    }

    /// Sends bounded message bytes to the live operation.
    pub fn update(&mut self, request: OperationRequest<'_>) -> Result<Vec<u8>, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.update(request, &mut self.broker)
    }

    /// Finishes and tombstones the live operation.
    pub fn finish(&mut self, request: FinishRequest<'_>) -> Result<FinishResult, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.finish(request, &mut self.broker)
    }

    /// Aborts and tombstones the live operation.
    pub fn abort(&mut self, request: OperationRequest<'_>) -> Result<(), DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.abort(request, &mut self.broker)
    }

    /// Deletes the retained broker key.
    pub fn delete(&mut self, request: DeleteRequest) -> Result<DonorKeyState, DonorError> {
        let service = self.service.as_mut().ok_or(DonorError::Unpaired)?;
        service.delete(request, &mut self.broker)
    }

    /// Invalidates all retained state when the authenticated peer disappears.
    pub fn peer_died(&mut self) {
        if let Some(service) = self.service.as_mut() {
            service.peer_died(&mut self.broker);
        }
    }
}
