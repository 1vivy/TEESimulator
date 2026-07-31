use rka_sidecar::donor::{
    BrokerBegin, BrokerFailure, BrokerGenerate, DonorBroker, GeneratedKey, PublicKeyResult,
    RemoteKeyHandle, RemoteOperationHandle, RkpKeyHandle,
};

#[derive(Debug, Default)]
pub struct FakeBroker {
    pub generated_requests: usize,
    pub begin_calls: usize,
    pub abort_calls: usize,
    pub finish_calls: usize,
    pub delete_calls: usize,
    pub fail_generate: bool,
    pub forced_operation: Option<RemoteOperationHandle>,
    pub forced_key: Option<RemoteKeyHandle>,
    pub fail_update_aad: bool,
    pub fail_delete: bool,
}

impl DonorBroker for FakeBroker {
    fn generate(&mut self, request: BrokerGenerate<'_>) -> Result<GeneratedKey, BrokerFailure> {
        self.generated_requests += 1;
        if self.fail_generate {
            return Err(BrokerFailure::Rejected);
        }
        assert_eq!(request.rkp_handle, RkpKeyHandle::new([0xb1; 32]));
        assert_ne!(request.envelope_hash, [0; 32]);
        assert_eq!(request.prior_transcript_hash, [0xc1; 32]);
        let suffix = u8::try_from(self.generated_requests).map_err(|_| BrokerFailure::Rejected)?;
        Ok(GeneratedKey::new(
            self.forced_key
                .unwrap_or_else(|| RemoteKeyHandle::new([0xd0 | suffix; 16])),
            vec![b"leaf".to_vec(), b"root".to_vec()],
            [0xd2; 32],
            [0xd3; 32],
        ))
    }

    fn begin(&mut self, _request: BrokerBegin) -> Result<RemoteOperationHandle, BrokerFailure> {
        self.begin_calls += 1;
        let suffix = u8::try_from(self.begin_calls).map_err(|_| BrokerFailure::Rejected)?;
        Ok(self
            .forced_operation
            .unwrap_or_else(|| RemoteOperationHandle::new([0xe0 | suffix; 16])))
    }

    fn update_aad(
        &mut self,
        _operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<usize, BrokerFailure> {
        if self.fail_update_aad {
            return Err(BrokerFailure::Rejected);
        }
        Ok(input.len())
    }

    fn update(
        &mut self,
        _operation: RemoteOperationHandle,
        input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        Ok(input.to_vec())
    }

    fn finish(
        &mut self,
        _operation: RemoteOperationHandle,
        _input: &[u8],
    ) -> Result<Vec<u8>, BrokerFailure> {
        self.finish_calls += 1;
        Ok(vec![0x30, 0x01, 0x01])
    }

    fn abort(&mut self, _operation: RemoteOperationHandle) -> Result<(), BrokerFailure> {
        self.abort_calls += 1;
        Ok(())
    }

    fn delete(&mut self, _key: RemoteKeyHandle) -> Result<(), BrokerFailure> {
        self.delete_calls += 1;
        if self.fail_delete {
            return Err(BrokerFailure::Rejected);
        }
        Ok(())
    }

    fn get(&mut self, _key: RemoteKeyHandle) -> Result<PublicKeyResult, BrokerFailure> {
        Err(BrokerFailure::Unavailable)
    }
}
