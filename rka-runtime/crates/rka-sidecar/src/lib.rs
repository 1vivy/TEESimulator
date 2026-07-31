//! Process surface for the separate RKA sidecar executable.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Write},
};

use thiserror::Error;

/// Authenticated, bounded broker bridge.
pub mod bridge;

/// Stable process version emitted by the manual health surface.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_PROFILE_BYTES: u64 = 4096;

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

    fn validate(self) -> Result<(), SidecarError> {
        let state_root = env::var_os("RKA_STATE_ROOT").ok_or(SidecarError::RuntimeContext)?;
        let profile = env::var_os("RKA_PROFILE_PATH").ok_or(SidecarError::RuntimeContext)?;
        let root_metadata =
            fs::symlink_metadata(state_root).map_err(|_| SidecarError::RuntimeContext)?;
        let profile_metadata =
            fs::symlink_metadata(&profile).map_err(|_| SidecarError::RuntimeContext)?;
        if !root_metadata.file_type().is_dir()
            || !profile_metadata.file_type().is_file()
            || profile_metadata.len() > MAX_PROFILE_BYTES
        {
            return Err(SidecarError::RuntimeContext);
        }
        let profile = fs::read_to_string(profile).map_err(|_| SidecarError::RuntimeContext)?;
        let mut version = false;
        let mut role = None;
        let mut epoch = false;
        for line in profile.lines() {
            match line {
                "version=1" if !version => version = true,
                "role=DONOR" if role.is_none() => role = Some(Self::Donor),
                "role=CANDIDATE" if role.is_none() => role = Some(Self::Candidate),
                value if value.starts_with("profile_epoch=") && !epoch => {
                    let epoch_value = &value["profile_epoch=".len()..];
                    if epoch_value.is_empty()
                        || !epoch_value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(SidecarError::RuntimeContext);
                    }
                    epoch = true;
                }
                _ => return Err(SidecarError::RuntimeContext),
            }
        }
        if version && epoch && role == Some(self) {
            Ok(())
        } else {
            Err(SidecarError::RuntimeContext)
        }
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
