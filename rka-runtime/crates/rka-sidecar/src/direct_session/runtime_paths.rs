use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
};

#[cfg(test)]
use crate::candidate::{CandidateId, CandidateLayout};

use super::DirectSessionError;

const LOCAL_BRIDGE_SOCKET: &str = "broker.sock";

pub(super) fn diagnostic(state: &Path, status: &str) {
    append_diagnostic(&state.join("run/direct-session.diagnostic"), status);
}

#[cfg(test)]
pub(super) fn candidate_diagnostic(state: &Path, candidate: &CandidateId, status: &str) {
    append_diagnostic(&candidate_diagnostic_path(state, candidate), status);
}

fn append_diagnostic(path: &Path, status: &str) {
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err()
        || fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_file())
    {
        return;
    }
    if let Ok(mut output) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(output, "{status}");
    }
}

#[cfg(test)]
pub(super) fn candidate_diagnostic_path(state: &Path, candidate: &CandidateId) -> PathBuf {
    CandidateLayout::new(state, candidate)
        .root()
        .join("run/direct-session.diagnostic")
}

#[cfg(test)]
pub(super) fn candidate_local_socket_path(state: &Path, candidate: &CandidateId) -> PathBuf {
    local_socket_path(CandidateLayout::new(state, candidate).root())
}

pub(super) fn local_socket_path(state: &Path) -> PathBuf {
    state.join("run/sockets").join(LOCAL_BRIDGE_SOCKET)
}

pub(super) fn bind_local(state: &Path) -> Result<UnixListener, DirectSessionError> {
    let directory = state.join("run/sockets");
    fs::create_dir_all(&directory).map_err(|_| DirectSessionError::Io)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| DirectSessionError::Io)?;
    let path = directory.join(LOCAL_BRIDGE_SOCKET);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(DirectSessionError::Io),
    }
    let listener = UnixListener::bind(path).map_err(|_| DirectSessionError::Io)?;
    fs::set_permissions(
        directory.join(LOCAL_BRIDGE_SOCKET),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| DirectSessionError::Io)?;
    Ok(listener)
}
