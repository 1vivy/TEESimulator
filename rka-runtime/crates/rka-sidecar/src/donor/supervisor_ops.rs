use crate::candidate::AuthenticatedCandidateContext;

use super::{
    BeginRequest, BeginResult, DeleteRequest, DonorBroker, DonorError, DonorKeyState,
    DonorSupervisor, FinishRequest, FinishResult, GenerateRequest, GenerateResult,
    OperationRequest, PublicKeyResult, shard::shard_mut,
};

impl<B: DonorBroker> DonorSupervisor<B> {
    /// Dispatches one frame only inside its authenticated candidate shard.
    pub fn dispatch(
        &mut self,
        context: &AuthenticatedCandidateContext,
        frame: &[u8],
    ) -> Result<Vec<u8>, DonorError> {
        self.ensure_candidate(context)?;
        super::dispatch::dispatch(self, context, frame)
    }

    /// Generates one key inside the authenticated candidate shard.
    pub fn generate(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: GenerateRequest<'_>,
    ) -> Result<GenerateResult, DonorError> {
        self.ensure_candidate(context)?;
        let alias = request.alias;
        let generated = {
            let (shards, broker) = (&mut self.shards, &mut self.broker);
            broker.bind_candidate(context.candidate());
            shard_mut(shards, context)?
                .service
                .generate(request, broker)?
        };
        self.register_generated_key(context, alias)?;
        Ok(generated)
    }

    /// Returns one key only from the authenticated candidate shard.
    pub fn get(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: DeleteRequest,
    ) -> Result<&PublicKeyResult, DonorError> {
        self.ensure_candidate(context)?;
        shard_mut(&mut self.shards, context)?.service.get(request)
    }

    /// Begins one operation inside the authenticated candidate shard.
    pub fn begin(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: BeginRequest,
    ) -> Result<BeginResult, DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?.service.begin(request, broker)
    }

    /// Sends associated data only to the authenticated candidate shard.
    pub fn update_aad(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: OperationRequest<'_>,
    ) -> Result<usize, DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?
            .service
            .update_aad(request, broker)
    }

    /// Sends message bytes only to the authenticated candidate shard.
    pub fn update(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: OperationRequest<'_>,
    ) -> Result<Vec<u8>, DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?.service.update(request, broker)
    }

    /// Finishes one operation inside the authenticated candidate shard.
    pub fn finish(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: FinishRequest<'_>,
    ) -> Result<FinishResult, DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?.service.finish(request, broker)
    }

    /// Aborts one operation inside the authenticated candidate shard.
    pub fn abort(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: OperationRequest<'_>,
    ) -> Result<(), DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?.service.abort(request, broker)
    }

    /// Deletes one key only from the authenticated candidate shard.
    pub fn delete(
        &mut self,
        context: &AuthenticatedCandidateContext,
        request: DeleteRequest,
    ) -> Result<DonorKeyState, DonorError> {
        self.ensure_candidate(context)?;
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        broker.bind_candidate(context.candidate());
        shard_mut(shards, context)?.service.delete(request, broker)
    }

    /// Returns redacted state only from the authenticated candidate shard.
    pub fn key_state(
        &self,
        context: &AuthenticatedCandidateContext,
        alias: [u8; 16],
    ) -> Result<Option<DonorKeyState>, DonorError> {
        self.authenticate(context)?;
        Ok(self
            .shards
            .get(context.candidate())
            .ok_or(DonorError::Unpaired)?
            .service
            .key_state(alias))
    }

    /// Exposes the injected broker for closed integration fixtures.
    #[doc(hidden)]
    #[must_use]
    pub const fn broker(&self) -> &B {
        &self.broker
    }
}
