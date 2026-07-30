//! Process surface for the separate RKA sidecar executable.

#![forbid(unsafe_code)]

use std::{
    ffi::OsStr,
    io::{self, Write},
};

use thiserror::Error;

/// Authenticated, bounded broker bridge.
pub mod bridge;

/// Stable process version emitted by the manual health surface.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Sidecar command failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SidecarError {
    /// The process received an unsupported command.
    #[error("unsupported command; expected --version or health")]
    UnsupportedCommand,
    /// Writing the bounded response failed.
    #[error("sidecar output failed")]
    Output(#[from] io::Error),
}

/// Runs the bounded command surface using caller-provided streams.
pub fn run(command: &OsStr, output: &mut impl Write) -> Result<(), SidecarError> {
    match command.to_str() {
        Some("--version") => writeln!(output, "rka-sidecar {VERSION}").map_err(SidecarError::from),
        Some("health") => writeln!(output, "healthy").map_err(SidecarError::from),
        Some(_) | None => Err(SidecarError::UnsupportedCommand),
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

        assert!(result.is_ok());
        assert_eq!(output, b"rka-sidecar 0.1.0\n");
    }

    #[test]
    fn health_command_reports_readiness() {
        let mut output = Vec::new();
        let result = run(OsStr::new("health"), &mut output);

        assert!(result.is_ok());
        assert_eq!(output, b"healthy\n");
    }
}
