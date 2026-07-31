use std::fmt;

use thiserror::Error;

use crate::{MAX_STATE_BYTES, StateError, StateStore, validate_record};

const QUARANTINE_KEY: &[u8] = b"rkp-quarantine-v1";
const MAX_HANDLES: usize = 20;

/// Material that must never become usable after an ambiguous mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousMaterial {
    request_id: [u8; 16],
    batch_id: [u8; 16],
    handles: Vec<[u8; 32]>,
}

impl AmbiguousMaterial {
    /// Parses one exact request, batch, and nonempty unique handle set.
    pub fn new(
        request_id: [u8; 16],
        batch_id: [u8; 16],
        handles: Vec<[u8; 32]>,
    ) -> Result<Self, QuarantineError> {
        if handles.is_empty()
            || handles.len() > MAX_HANDLES
            || handles.iter().enumerate().any(|(index, handle)| {
                handles
                    .get(..index)
                    .is_some_and(|prior| prior.contains(handle))
            })
        {
            return Err(QuarantineError::Material);
        }
        Ok(Self {
            request_id,
            batch_id,
            handles,
        })
    }
}

/// Crash/restart point requiring quarantine rather than replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MutationCrashState {
    /// IRPC key generation may have mutated hardware.
    RkpKeyGenerating,
    /// The certificate request upload may have begun.
    CsrPosting,
    /// The upload outcome is already known to be ambiguous.
    PostAmbiguous,
    /// Foreground application key generation may have mutated hardware.
    AppKeyGenerating,
}

/// Durable reason material is unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuarantineReason {
    /// A hardware generation call was interrupted.
    GeneratingCrash,
    /// A request upload may have reached the remote endpoint.
    PostAmbiguous,
}

/// Required broker action for each mapped key handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuarantineAction {
    /// Delete or revoke the broker's mapping.
    Discard,
    /// Zero the broker's retained bytes.
    Wipe,
}

/// Exact crash state and material processed as one recovery input.
#[derive(Clone, Copy, Debug)]
pub struct CrashRecovery<'a> {
    state: MutationCrashState,
    material: &'a AmbiguousMaterial,
}

impl<'a> CrashRecovery<'a> {
    /// Binds one crash state to its exact request material.
    #[must_use]
    pub const fn new(state: MutationCrashState, material: &'a AmbiguousMaterial) -> Self {
        Self { state, material }
    }
}

/// One-call broker cleanup boundary used only after quarantine is durable.
pub trait QuarantineActions {
    /// Cancels the authenticated broker request.
    fn cancel(&mut self);

    /// Applies one exact action to one exact mapped handle.
    fn apply(&mut self, handle: [u8; 32], action: QuarantineAction);
}

/// Durable fail-closed quarantine ledger.
pub struct QuarantineLedger<'a> {
    store: &'a dyn StateStore,
}

impl<'a> QuarantineLedger<'a> {
    /// Binds a ledger to its durable state store.
    #[must_use]
    pub const fn new(store: &'a dyn StateStore) -> Self {
        Self { store }
    }

    /// Persists terminal quarantine before one cancellation and per-handle cleanup.
    pub fn recover_crash(
        &mut self,
        recovery: CrashRecovery<'_>,
        actions: &mut dyn QuarantineActions,
    ) -> Result<(), QuarantineError> {
        if self.load()?.is_some() {
            return Err(QuarantineError::AlreadyQuarantined);
        }
        let reason = match recovery.state {
            MutationCrashState::RkpKeyGenerating | MutationCrashState::AppKeyGenerating => {
                QuarantineReason::GeneratingCrash
            }
            MutationCrashState::CsrPosting | MutationCrashState::PostAmbiguous => {
                QuarantineReason::PostAmbiguous
            }
        };
        let encoded = encode(reason, recovery.material)?;
        validate_record(&encoded)?;
        self.store.replace(QUARANTINE_KEY, &encoded)?;
        actions.cancel();
        for handle in &recovery.material.handles {
            actions.apply(*handle, QuarantineAction::Discard);
            actions.apply(*handle, QuarantineAction::Wipe);
        }
        Ok(())
    }

    /// Returns false for an exact quarantined attempt after any restart.
    pub fn activation_allowed(
        &self,
        material: &AmbiguousMaterial,
    ) -> Result<bool, QuarantineError> {
        Ok(self
            .load()?
            .is_none_or(|(_, quarantined)| quarantined != *material))
    }

    /// Reads the retained reason without changing terminal state.
    pub fn reason(&self) -> Result<Option<QuarantineReason>, QuarantineError> {
        Ok(self.load()?.map(|(reason, _)| reason))
    }

    fn load(&self) -> Result<Option<(QuarantineReason, AmbiguousMaterial)>, QuarantineError> {
        let mut stored = vec![0_u8; MAX_STATE_BYTES];
        let size = match self.store.read(QUARANTINE_KEY, &mut stored) {
            Ok(size) => size,
            Err(StateError::Missing) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        stored.truncate(size);
        decode(&stored).map(Some)
    }
}

impl fmt::Debug for QuarantineLedger<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuarantineLedger")
            .finish_non_exhaustive()
    }
}

/// Durable quarantine failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum QuarantineError {
    /// Request, batch, or handles are invalid.
    #[error("ambiguous material is invalid")]
    Material,
    /// This terminal record was already processed.
    #[error("material is already quarantined")]
    AlreadyQuarantined,
    /// Stored bytes do not match the canonical schema.
    #[error("quarantine record is corrupt")]
    Corrupt,
    /// The durable state boundary failed.
    #[error(transparent)]
    State(#[from] StateError),
}

fn encode(
    reason: QuarantineReason,
    material: &AmbiguousMaterial,
) -> Result<Vec<u8>, QuarantineError> {
    let capacity = material
        .handles
        .len()
        .checked_mul(32)
        .and_then(|size| size.checked_add(38))
        .ok_or(QuarantineError::Material)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(b"RKQ1");
    bytes.push(match reason {
        QuarantineReason::GeneratingCrash => 1,
        QuarantineReason::PostAmbiguous => 2,
    });
    bytes.extend_from_slice(&material.request_id);
    bytes.extend_from_slice(&material.batch_id);
    bytes.push(u8::try_from(material.handles.len()).map_err(|_| QuarantineError::Material)?);
    material
        .handles
        .iter()
        .for_each(|handle| bytes.extend_from_slice(handle));
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<(QuarantineReason, AmbiguousMaterial), QuarantineError> {
    if bytes.len() < 38 || bytes.get(..4) != Some(b"RKQ1") {
        return Err(QuarantineError::Corrupt);
    }
    let reason = match bytes.get(4) {
        Some(1) => QuarantineReason::GeneratingCrash,
        Some(2) => QuarantineReason::PostAmbiguous,
        Some(_) | None => return Err(QuarantineError::Corrupt),
    };
    let request_id = bytes
        .get(5..21)
        .ok_or(QuarantineError::Corrupt)?
        .try_into()
        .map_err(|_| QuarantineError::Corrupt)?;
    let batch_id = bytes
        .get(21..37)
        .ok_or(QuarantineError::Corrupt)?
        .try_into()
        .map_err(|_| QuarantineError::Corrupt)?;
    let count = usize::from(*bytes.get(37).ok_or(QuarantineError::Corrupt)?);
    let expected = 38_usize
        .checked_add(count.checked_mul(32).ok_or(QuarantineError::Corrupt)?)
        .ok_or(QuarantineError::Corrupt)?;
    if bytes.len() != expected {
        return Err(QuarantineError::Corrupt);
    }
    let handles = bytes
        .get(38..)
        .ok_or(QuarantineError::Corrupt)?
        .chunks_exact(32)
        .map(|handle| handle.try_into().map_err(|_| QuarantineError::Corrupt))
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    Ok((
        reason,
        AmbiguousMaterial::new(request_id, batch_id, handles)?,
    ))
}
