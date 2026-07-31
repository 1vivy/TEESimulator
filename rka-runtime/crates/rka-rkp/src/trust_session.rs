use std::sync::Mutex;

use thiserror::Error;

use crate::{RootBundle, RootRotationAuthorization, ValidationError};

#[derive(Debug)]
struct TrustState {
    bundle: RootBundle,
    accepting: bool,
    active: usize,
}

/// Atomically pins an immutable root bundle for each provisioning session.
#[derive(Debug)]
pub struct RootTrustManager {
    state: Mutex<TrustState>,
}

impl RootTrustManager {
    /// Creates a manager accepting sessions against `bundle`.
    #[must_use]
    pub const fn new(bundle: RootBundle) -> Self {
        Self {
            state: Mutex::new(TrustState {
                bundle,
                accepting: true,
                active: 0,
            }),
        }
    }

    /// Begins a session and freezes one epoch/root snapshot until the guard drops.
    pub fn begin(&self) -> Result<ProvisioningSession<'_>, TrustSessionError> {
        let mut state = self.state.lock().map_err(|_| TrustSessionError::Poisoned)?;
        if !state.accepting {
            return Err(TrustSessionError::Paused);
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or(TrustSessionError::Poisoned)?;
        let bundle = state.bundle.clone();
        drop(state);
        Ok(ProvisioningSession {
            manager: self,
            bundle,
        })
    }

    /// Pauses admission and rotates only after every pinned session is quiescent.
    #[allow(
        clippy::too_many_arguments,
        reason = "rotation atomically binds epoch, roots, and authorization"
    )]
    pub fn pause_and_rotate(
        &self,
        next_epoch: u64,
        pins: Vec<[u8; 32]>,
        authorization: Option<&RootRotationAuthorization>,
    ) -> Result<(), TrustSessionError> {
        let mut state = self.state.lock().map_err(|_| TrustSessionError::Poisoned)?;
        state.accepting = false;
        if state.active != 0 {
            return Err(TrustSessionError::ActiveSessions);
        }
        state.bundle = state
            .bundle
            .rotate(next_epoch, pins, authorization)
            .map_err(TrustSessionError::Rotation)?;
        state.accepting = true;
        drop(state);
        Ok(())
    }
}

/// One immutable trust snapshot held across fetch, validation, and activation.
#[derive(Debug)]
pub struct ProvisioningSession<'a> {
    manager: &'a RootTrustManager,
    bundle: RootBundle,
}

impl ProvisioningSession<'_> {
    /// Returns the exact bundle pinned when this session began.
    #[must_use]
    pub const fn roots(&self) -> &RootBundle {
        &self.bundle
    }
}

impl Drop for ProvisioningSession<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.manager.state.lock() {
            state.active = state.active.saturating_sub(1);
        }
    }
}

/// Root-session admission and rotation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TrustSessionError {
    /// New sessions are paused for a pending rotation.
    #[error("root trust admission is paused")]
    Paused,
    /// Existing provisioning sessions have not reached quiescence.
    #[error("root rotation is waiting for active sessions")]
    ActiveSessions,
    /// The proposed root rotation failed authorization.
    #[error("root rotation failed")]
    Rotation(ValidationError),
    /// The process cannot safely recover shared trust state.
    #[error("root trust state is unavailable")]
    Poisoned,
}
