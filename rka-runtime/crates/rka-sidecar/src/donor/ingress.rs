#![allow(
    missing_docs,
    reason = "closed local ingress types expose only behavior-named constructors and outcomes"
)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    time::Duration,
};

use rustix::net::sockopt::socket_peercred;
use thiserror::Error;

use super::DonorRuntime;

const MAX_FRAME_BYTES: usize = 1_048_576;
const IO_DEADLINE: Duration = Duration::from_secs(5);

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
    path: PathBuf,
}

impl DonorIngress {
    pub fn bind(state_root: &Path) -> Result<Self, DonorIngressError> {
        Self::bind_for_owner(state_root, 0, 0)
    }

    #[allow(
        clippy::similar_names,
        reason = "Unix ownership checks require distinct uid and gid coordinates"
    )]
    fn bind_for_owner(
        state_root: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DonorIngressError> {
        let directory = state_root.join("run/sockets");
        private_directory(&directory, expected_uid, expected_gid)?;
        let path = directory.join("donor-rka.sock");
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != expected_uid
                || metadata.gid() != expected_gid
            {
                return Err(DonorIngressError::Path);
            }
            fs::remove_file(&path).map_err(|_| DonorIngressError::Io)?;
        }
        let listener = UnixListener::bind(&path).map_err(|_| DonorIngressError::Io)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| DonorIngressError::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| DonorIngressError::Io)?;
        Ok(Self { listener, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn serve_once(
        &self,
        runtime: &mut DonorRuntime,
    ) -> Result<ServeOutcome, DonorIngressError> {
        let (mut stream, _) = match self.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(ServeOutcome::Idle);
            }
            Err(_) => return Err(DonorIngressError::Io),
        };
        let credentials = socket_peercred(&stream).map_err(|_| DonorIngressError::Peer)?;
        if credentials.uid.as_raw() != 0 || credentials.gid.as_raw() != 0 {
            return Err(DonorIngressError::Peer);
        }
        stream
            .set_read_timeout(Some(IO_DEADLINE))
            .map_err(|_| DonorIngressError::Io)?;
        stream
            .set_write_timeout(Some(IO_DEADLINE))
            .map_err(|_| DonorIngressError::Io)?;
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| DonorIngressError::Io)?;
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| DonorIngressError::Bounds)?;
        if !(1..=MAX_FRAME_BYTES).contains(&length) {
            return Err(DonorIngressError::Bounds);
        }
        let mut request = vec![0_u8; length];
        stream
            .read_exact(&mut request)
            .map_err(|_| DonorIngressError::Io)?;
        let response = runtime
            .dispatch_frame(&request)
            .map_err(|_| DonorIngressError::Runtime)?;
        request.fill(0);
        let response_length =
            u32::try_from(response.len()).map_err(|_| DonorIngressError::Bounds)?;
        stream
            .write_all(&response_length.to_be_bytes())
            .and_then(|()| stream.write_all(&response))
            .map_err(|_| DonorIngressError::Io)?;
        Ok(ServeOutcome::Dispatched)
    }
}

impl Drop for DonorIngress {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[allow(
    clippy::similar_names,
    reason = "Unix ownership checks require distinct uid and gid coordinates"
)]
fn private_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DonorIngressError> {
    fs::create_dir_all(path).map_err(|_| DonorIngressError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| DonorIngressError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| DonorIngressError::Path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o077 != 0
    {
        return Err(DonorIngressError::Path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn stale_owned_socket_is_replaced_with_private_mode_and_cleaned() {
        // Given
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rka-ingress-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let sockets = root.join("run/sockets");
        fs::create_dir_all(&sockets).unwrap();
        fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700)).unwrap();
        let path = sockets.join("donor-rka.sock");
        drop(UnixListener::bind(&path).unwrap());
        let metadata = fs::metadata(&sockets).unwrap();

        // When
        let ingress = DonorIngress::bind_for_owner(&root, metadata.uid(), metadata.gid()).unwrap();

        // Then
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(ingress);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
