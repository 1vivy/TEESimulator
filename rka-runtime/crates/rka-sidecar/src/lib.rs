//! Process surface for the separate RKA sidecar executable.

#![forbid(unsafe_code)]

use std::{
    ffi::OsStr,
    io::{self, Write},
};

use thiserror::Error;

#[doc(hidden)]
pub mod direct_activation;
mod direct_bridge;
pub mod direct_identity;
pub mod direct_profile;
#[doc(hidden)]
pub mod direct_session;
mod provision_activation;
mod provisioning;
mod provisioning_io;
mod trust_runtime;

/// Paired-only donor policy and lifecycle service.
pub mod donor;

pub use provisioning::{
    ProvisioningActivationStage, ProvisioningFailureStage, ProvisioningRunError,
    ProvisioningValidationStage, provision_once,
};
pub use trust_runtime::{committed_profile_epoch, dispatch_rotation};

/// Authenticated, bounded broker bridge.
pub mod bridge;

/// Stable process version emitted by the manual health surface.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Sidecar command failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SidecarError {
    /// The process received an unsupported command.
    #[error("unsupported command")]
    UnsupportedCommand,
    #[error("invalid role runtime context")]
    /// The root-owned state or profile path is missing or invalid.
    RuntimeContext,
    /// Writing the bounded response failed.
    #[error("sidecar output failed")]
    Output(#[from] io::Error),
}

/// Fixed roles permitted for a supervised sidecar process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LifecycleRole {
    /// Donor listener/client role.
    Donor,
    /// Candidate client role.
    Candidate,
}

impl LifecycleRole {
    /// Parses the exact command-line role token.
    pub fn parse(command: &OsStr) -> Result<Self, SidecarError> {
        match command.to_str() {
            Some("donor") => Ok(Self::Donor),
            Some("candidate") => Ok(Self::Candidate),
            Some(_) | None => Err(SidecarError::UnsupportedCommand),
        }
    }

    const fn status_name(self) -> &'static str {
        match self {
            Self::Donor => "donor",
            Self::Candidate => "candidate",
        }
    }

    const fn profile_line(self) -> &'static str {
        match self {
            Self::Donor => "role=DONOR",
            Self::Candidate => "role=CANDIDATE",
        }
    }

    fn validate(self) -> Result<(), SidecarError> {
        direct_profile::consume(self)
    }
}

/// Runs the bounded command surface using caller-provided streams.
pub fn run(
    command: &OsStr,
    output: &mut impl Write,
) -> Result<Option<LifecycleRole>, SidecarError> {
    match command.to_str() {
        Some("--version") => writeln!(output, "rka-sidecar {VERSION}")
            .map(|()| None)
            .map_err(SidecarError::from),
        Some("health") => writeln!(output, "healthy")
            .map(|()| None)
            .map_err(SidecarError::from),
        Some(_) | None => {
            let role = LifecycleRole::parse(command)?;
            role.validate()?;
            writeln!(output, "role={} status=READY", role.status_name())?;
            output.flush()?;
            Ok(Some(role))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::run;

    #[test]
    fn version_command_reports_stable_binary_name() {
        let mut output = Vec::new();
        let result = run(OsStr::new("--version"), &mut output);

        assert!(matches!(result, Ok(None)));
        assert_eq!(output, b"rka-sidecar 0.1.0\n");
    }

    #[test]
    fn health_command_reports_readiness() {
        let mut output = Vec::new();
        let result = run(OsStr::new("health"), &mut output);

        assert!(matches!(result, Ok(None)));
        assert_eq!(output, b"healthy\n");
    }
}
