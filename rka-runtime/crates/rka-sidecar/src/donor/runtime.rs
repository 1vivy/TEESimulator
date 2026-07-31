use std::path::{Path, PathBuf};

use rka_state::{CertifiedLeaseMetadata, PairedActivationRecord, RkpLeaseBatch};

use super::{
    BeginRequest, BeginResult, BridgeDonorBroker, DeleteRequest, DonorError, DonorKeyState,
    DonorRkaService, FinishRequest, FinishResult, GenerateRequest, GenerateResult,
    OperationRequest, PairedPolicy, PublicKeyResult,
};
use crate::provisioning_io::FileStateStore;

#[allow(
    dead_code,
    reason = "Task 24 calls this typed boundary only after transport authentication"
)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "re-exported as the crate-private Task 24 activation boundary"
)]
pub(crate) fn activate_authenticated_pair(
    state_root: &Path,
    activation: PairedActivationRecord,
) -> Result<(), DonorError> {
    activation
        .persist(&FileStateStore::new(state_root))
        .map_err(|_| DonorError::Storage)
}

/// Production donor lifecycle wired to the authenticated Android broker bridge.
#[derive(Debug)]
pub struct DonorRuntime {
    pub(super) service: Option<DonorRkaService>,
    pub(super) broker: BridgeDonorBroker,
    pub(super) trust: Option<RuntimeTrust>,
    pub(super) state_root: Option<PathBuf>,
    pub(super) transcript: Option<super::state::TranscriptJournal>,
}

#[derive(Debug)]
pub(super) struct RuntimeTrust {
    pub(super) pair: PairedActivationRecord,
    pub(super) leases: Vec<CertifiedLeaseMetadata>,
}

impl DonorRuntime {
    /// Creates a dormant donor role without accepting unpaired requests.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            service: None,
            broker: BridgeDonorBroker::new(socket),
            trust: None,
            state_root: None,
            transcript: None,
        }
    }

    /// Reopens only an authenticated pair backed by an active certified lease.
    #[must_use]
    pub fn open(state_root: &Path, socket: &Path) -> Self {
        let store = FileStateStore::new(state_root);
        let admitted = PairedActivationRecord::load(&store)
            .ok()
            .zip(RkpLeaseBatch::load_active(&store).ok())
            .and_then(|(pair, leases)| {
                let lease = leases.leases().first()?.metadata();
                let irpc = *lease.irpc_identity_hash.as_bytes();
                let lease_epoch = lease.profile_epoch;
                let consistent = leases.leases().iter().all(|entry| {
                    entry.metadata().profile_epoch == pair.profile_epoch
                        && entry.metadata().irpc_identity_hash.as_bytes() == &irpc
                });
                if !consistent || lease_epoch != pair.profile_epoch {
                    return None;
                }
                let service = DonorRkaService::new_durable(
                    PairedPolicy::new(
                        pair.peer_spki_hash,
                        pair.profile_id_hash,
                        pair.profile_epoch,
                        pair.candidate_identity_hash,
                        irpc,
                        pair.prior_transcript_hash,
                    ),
                    state_root,
                );
                let metadata = leases
                    .leases()
                    .iter()
                    .map(|entry| *entry.metadata())
                    .collect();
                let transcript =
                    super::state::TranscriptJournal::open(state_root, pair.prior_transcript_hash)
                        .ok()?;
                transcript.committed().ok()?;
                Some((
                    service,
                    RuntimeTrust {
                        pair,
                        leases: metadata,
                    },
                    transcript,
                ))
            });
        let (service, trust, transcript) = admitted
            .map_or((None, None, None), |(service, trust, transcript)| {
                (Some(service), Some(trust), Some(transcript))
            });
        Self {
            service,
            broker: BridgeDonorBroker::new(socket),
            trust,
            state_root: Some(state_root.to_path_buf()),
            transcript,
        }
    }

    /// Reports whether both trusted durable records admitted the donor role.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.service.is_some()
    }

    /// Decodes and dispatches one authenticated canonical RKA request.
    pub fn dispatch_frame(&mut self, encoded: &[u8]) -> Result<Vec<u8>, DonorError> {
        super::dispatch::dispatch(self, encoded)
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
