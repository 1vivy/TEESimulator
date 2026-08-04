use std::path::Path;

use rka_state::{CertifiedLeaseMetadata, PairedActivationRecord, RkpLeaseBatch, StateStore};

use super::{
    BridgeDonorBroker, CandidateShard, DonorBroker, DonorError, DonorSupervisor, PairedPolicy,
    shard::DurableShardState, state::TranscriptJournal,
};
use crate::{
    candidate::{
        AuthenticatedCandidateContext, CandidateLayout, PairingAdmission, PairingCatalog,
        authority::{self, StateAuthority},
    },
    provisioning_io::FileStateStore,
};

/// Production donor supervisor backed by the authenticated Android broker.
pub type DonorRuntime = DonorSupervisor<BridgeDonorBroker>;

#[derive(Debug)]
pub(super) struct RuntimeTrust {
    pub(super) pair: PairedActivationRecord,
    pub(super) leases: Vec<CertifiedLeaseMetadata>,
}

#[derive(Clone, Copy)]
struct RuntimeLocation<'a> {
    state_root: &'a Path,
    candidate_root: &'a Path,
}

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

impl DonorSupervisor<BridgeDonorBroker> {
    /// Creates a dormant donor without any authenticated candidate shard.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self::with_broker(PairingCatalog::empty(), BridgeDonorBroker::new(socket))
    }

    /// Reopens the authoritative candidate shard and its pairing catalog.
    #[must_use]
    pub fn open(state_root: &Path, socket: &Path) -> Self {
        match authority::resolve(state_root) {
            StateAuthority::Legacy => {
                let store = FileStateStore::new(state_root);
                Self::open_at(
                    RuntimeLocation {
                        state_root,
                        candidate_root: state_root,
                    },
                    socket,
                    &store,
                )
            }
            StateAuthority::Candidate(candidate_root) => {
                let store = FileStateStore::new(&candidate_root);
                Self::open_at(
                    RuntimeLocation {
                        state_root,
                        candidate_root: &candidate_root,
                    },
                    socket,
                    &store,
                )
            }
            StateAuthority::Invalid => Self::inactive(state_root, socket),
        }
    }

    /// Opens with an observable legacy store for fail-closed authority tests.
    #[doc(hidden)]
    #[must_use]
    pub fn open_with_legacy_store(
        state_root: &Path,
        socket: &Path,
        legacy_store: &dyn StateStore,
    ) -> Self {
        match authority::resolve(state_root) {
            StateAuthority::Legacy => Self::open_at(
                RuntimeLocation {
                    state_root,
                    candidate_root: state_root,
                },
                socket,
                legacy_store,
            ),
            StateAuthority::Candidate(candidate_root) => {
                let store = FileStateStore::new(&candidate_root);
                Self::open_at(
                    RuntimeLocation {
                        state_root,
                        candidate_root: &candidate_root,
                    },
                    socket,
                    &store,
                )
            }
            StateAuthority::Invalid => Self::inactive(state_root, socket),
        }
    }

    /// Reports whether at least one authenticated shard is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.shards.is_empty()
    }

    pub(crate) fn dispatch_frame(&mut self, encoded: &[u8]) -> Result<Vec<u8>, DonorError> {
        let context = self.local_candidate.ok_or(DonorError::Unpaired)?;
        self.dispatch(&context, encoded)
    }

    fn open_at(location: RuntimeLocation<'_>, socket: &Path, store: &dyn StateStore) -> Self {
        let Ok(pair) = PairedActivationRecord::load(store) else {
            return Self::inactive(location.state_root, socket);
        };
        let catalog = if let Ok(catalog) = PairingCatalog::load(location.state_root) {
            catalog
        } else {
            let mut catalog = PairingCatalog::empty();
            if catalog
                .admit(PairingAdmission {
                    peer_spki_hash: pair.peer_spki_hash,
                    profile_id_hash: pair.profile_id_hash,
                    profile_epoch: pair.profile_epoch,
                    candidate_identity_hash: pair.candidate_identity_hash,
                })
                .is_err()
            {
                return Self::inactive(location.state_root, socket);
            }
            catalog
        };
        let Ok(context) = catalog.lookup(
            pair.peer_spki_hash,
            pair.profile_id_hash,
            pair.profile_epoch,
        ) else {
            return Self::inactive(location.state_root, socket);
        };
        let Ok(shard) = load_at(location.candidate_root, store, &context) else {
            return Self::inactive(location.state_root, socket);
        };
        let mut runtime = Self::with_broker(catalog, BridgeDonorBroker::new(socket));
        runtime.shards.insert(*context.candidate(), shard);
        runtime.state_root = Some(location.state_root.to_path_buf());
        runtime.local_candidate = Some(context);
        runtime
    }

    fn inactive(state_root: &Path, socket: &Path) -> Self {
        let mut runtime = Self::new(socket);
        runtime.state_root = Some(state_root.to_path_buf());
        runtime
    }
}

impl<B: DonorBroker> DonorSupervisor<B> {
    /// Invalidates only the disconnected authenticated candidate shard.
    pub fn candidate_died(&mut self, candidate: &crate::candidate::CandidateId) {
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        if let Some(shard) = shards.get_mut(candidate) {
            broker.bind_candidate(candidate);
            shard.service.invalidate_all(broker);
        }
    }

    /// Invalidates every shard after donor broker death.
    pub fn broker_died(&mut self) {
        let (shards, broker) = (&mut self.shards, &mut self.broker);
        for (candidate, shard) in shards {
            broker.bind_candidate(candidate);
            shard.service.invalidate_all(broker);
        }
    }
}

pub(super) fn load_candidate(
    state_root: &Path,
    context: &AuthenticatedCandidateContext,
) -> Result<CandidateShard, DonorError> {
    let layout = CandidateLayout::new(state_root, context.candidate());
    let store = FileStateStore::new(layout.root());
    load_at(layout.root(), &store, context)
}

fn load_at(
    candidate_root: &Path,
    store: &dyn StateStore,
    context: &AuthenticatedCandidateContext,
) -> Result<CandidateShard, DonorError> {
    let pair = PairedActivationRecord::load(store).map_err(|_| DonorError::Storage)?;
    if pair.peer_spki_hash != *context.peer_spki_hash()
        || pair.profile_id_hash != *context.profile_id_hash()
        || pair.profile_epoch != context.profile_epoch()
        || pair.candidate_identity_hash != *context.candidate().as_bytes()
    {
        return Err(DonorError::Unpaired);
    }
    let lease_batch = RkpLeaseBatch::load_active(store).map_err(|_| DonorError::Storage)?;
    let first = lease_batch.leases().first().ok_or(DonorError::Unpaired)?;
    let irpc = *first.metadata().irpc_identity_hash.as_bytes();
    let consistent = lease_batch.leases().iter().all(|entry| {
        entry.metadata().profile_epoch == pair.profile_epoch
            && entry.metadata().irpc_identity_hash.as_bytes() == &irpc
    });
    if !consistent {
        return Err(DonorError::Unpaired);
    }
    let policy = PairedPolicy::new(
        pair.peer_spki_hash,
        pair.profile_id_hash,
        pair.profile_epoch,
        pair.candidate_identity_hash,
        irpc,
        pair.prior_transcript_hash,
    );
    let transcript = TranscriptJournal::open(candidate_root, pair.prior_transcript_hash)?;
    transcript.committed()?;
    CandidateShard::durable(
        context,
        policy,
        DurableShardState {
            trust: RuntimeTrust {
                pair,
                leases: lease_batch
                    .leases()
                    .iter()
                    .map(|entry| *entry.metadata())
                    .collect(),
            },
            replay_root: candidate_root.to_path_buf(),
            transcript,
        },
    )
}
