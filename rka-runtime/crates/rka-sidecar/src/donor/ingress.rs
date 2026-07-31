#![allow(
    clippy::similar_names,
    missing_docs,
    reason = "closed local ingress types expose only behavior-named constructors and outcomes"
)]

use std::{
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rustix::{
    fs::{AtFlags, FileType, Mode, fsync, statat, unlinkat},
    net::sockopt::socket_peercred,
    process::{getegid, geteuid},
};
use thiserror::Error;

use super::{
    DonorRuntime,
    ingress_io::{read_frame_until, write_response_until},
    ingress_path::{open_socket_directory, remove_stale_socket},
};

const IO_DEADLINE: Duration = Duration::from_secs(5);
pub(super) const SOCKET_NAME: &str = "donor-rka.sock";

#[derive(Debug, Error)]
pub enum DonorIngressError {
    #[error("local donor ingress path is not private")]
    Path,
    #[error("local donor ingress peer is not root")]
    Peer,
    #[error("local donor ingress frame is outside bounds")]
    Bounds,
    #[error("local donor ingress I/O failed")]
    Io,
    #[error("local donor runtime rejected the request")]
    Runtime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeOutcome {
    Idle,
    Dispatched,
}

#[derive(Debug)]
pub struct DonorIngress {
    listener: UnixListener,
    directory: OwnedFd,
    path: PathBuf,
}

impl DonorIngress {
    pub fn bind(state_root: &Path) -> Result<Self, DonorIngressError> {
        if geteuid().as_raw() != 0 || getegid().as_raw() != 0 {
            return Err(DonorIngressError::Path);
        }
        Self::bind_for_owner(state_root, 0, 0)
    }

    #[doc(hidden)]
    pub fn bind_for_owner_policy(
        state_root: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DonorIngressError> {
        Self::bind_for_owner(state_root, expected_uid, expected_gid)
    }

    fn bind_for_owner(
        state_root: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DonorIngressError> {
        let directory = open_socket_directory(state_root, expected_uid, expected_gid)?;
        remove_stale_socket(&directory, expected_uid, expected_gid)?;
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory.as_raw_fd(),
            SOCKET_NAME
        ));
        let listener = UnixListener::bind(&path).map_err(|_| DonorIngressError::Io)?;
        let socket = statat(&directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DonorIngressError::Path)?;
        if FileType::from_raw_mode(socket.st_mode) != FileType::Socket
            || socket.st_uid != expected_uid
            || socket.st_gid != expected_gid
        {
            return Err(DonorIngressError::Path);
        }
        rustix::fs::chmodat(
            &directory,
            SOCKET_NAME,
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )
        .map_err(|_| DonorIngressError::Io)?;
        fsync(&directory).map_err(|_| DonorIngressError::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| DonorIngressError::Io)?;
        Ok(Self {
            listener,
            directory,
            path: state_root.join("run/sockets").join(SOCKET_NAME),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn serve_once(
        &self,
        runtime: &mut DonorRuntime,
    ) -> Result<ServeOutcome, DonorIngressError> {
        self.serve_once_with_policy(runtime, IO_DEADLINE, 0, 0)
    }

    fn serve_once_with_policy(
        &self,
        runtime: &mut DonorRuntime,
        budget: Duration,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<ServeOutcome, DonorIngressError> {
        let started = Instant::now();
        let (stream, _) = match self.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(ServeOutcome::Idle);
            }
            Err(_) => return Err(DonorIngressError::Io),
        };
        let credentials = socket_peercred(&stream).map_err(|_| DonorIngressError::Peer)?;
        if credentials.uid.as_raw() != expected_uid || credentials.gid.as_raw() != expected_gid {
            return Err(DonorIngressError::Peer);
        }
        let request = read_frame_until(
            stream.try_clone().map_err(|_| DonorIngressError::Io)?,
            started,
            budget,
        )?;
        let response = runtime
            .dispatch_frame(&request)
            .map_err(|_| DonorIngressError::Runtime)?;
        let mut stream = stream;
        write_response_until(&mut stream, &response, started, budget)?;
        Ok(ServeOutcome::Dispatched)
    }

    #[doc(hidden)]
    pub fn read_frame_with_budget(
        stream: UnixStream,
        budget: Duration,
    ) -> Result<Vec<u8>, DonorIngressError> {
        read_frame_until(stream, Instant::now(), budget)
    }

    #[doc(hidden)]
    pub fn serve_once_for_peer_policy(
        &self,
        runtime: &mut DonorRuntime,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<ServeOutcome, DonorIngressError> {
        self.serve_once_with_policy(runtime, IO_DEADLINE, expected_uid, expected_gid)
    }
}

impl Drop for DonorIngress {
    fn drop(&mut self) {
        let _ = unlinkat(&self.directory, SOCKET_NAME, AtFlags::empty());
        let _ = fsync(&self.directory);
    }
}
