#![allow(
    clippy::similar_names,
    reason = "Unix ownership validation requires distinct uid and gid coordinates"
)]

use std::{
    ffi::OsStr,
    os::fd::OwnedFd,
    path::{Component, Path},
};

use rustix::{
    fs::{
        AtFlags, CWD, FileType, Mode, OFlags, fchmod, fstat, fsync, mkdirat, openat, statat,
        unlinkat,
    },
    io::Errno,
};

use super::{DonorIngressError, ingress::SOCKET_NAME};

pub(super) fn open_socket_directory(
    state_root: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<OwnedFd, DonorIngressError> {
    if !state_root.is_absolute() {
        return Err(DonorIngressError::Path);
    }
    let mut components = state_root.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(DonorIngressError::Path);
    }
    let mut parent =
        openat(CWD, "/", directory_flags(), Mode::empty()).map_err(|_| DonorIngressError::Path)?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(DonorIngressError::Path);
        };
        let final_state_component = components.peek().is_none();
        parent = open_or_create_directory(
            &parent,
            name,
            if final_state_component {
                expected_uid
            } else {
                0
            },
            if final_state_component {
                expected_gid
            } else {
                0
            },
            final_state_component,
        )?;
    }
    for name in ["run", "sockets"] {
        parent =
            open_or_create_directory(&parent, OsStr::new(name), expected_uid, expected_gid, true)?;
    }
    Ok(parent)
}

fn open_or_create_directory(
    parent: &OwnedFd,
    name: &OsStr,
    expected_uid: u32,
    expected_gid: u32,
    private: bool,
) -> Result<OwnedFd, DonorIngressError> {
    let directory = match openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => {
            mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                .map_err(|_| DonorIngressError::Io)?;
            fsync(parent).map_err(|_| DonorIngressError::Io)?;
            openat(parent, name, directory_flags(), Mode::empty())
                .map_err(|_| DonorIngressError::Path)?
        }
        Err(_) => return Err(DonorIngressError::Path),
    };
    if private {
        fchmod(&directory, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| DonorIngressError::Io)?;
    }
    let metadata = fstat(&directory).map_err(|_| DonorIngressError::Path)?;
    let insecure_mode = metadata.st_mode & 0o022 != 0 && metadata.st_mode & 0o1000 == 0;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != expected_uid
        || metadata.st_gid != expected_gid
        || insecure_mode
    {
        return Err(DonorIngressError::Path);
    }
    Ok(directory)
}

pub(super) fn remove_stale_socket(
    directory: &OwnedFd,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), DonorIngressError> {
    match statat(directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => {
            if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
                || metadata.st_uid != expected_uid
                || metadata.st_gid != expected_gid
            {
                return Err(DonorIngressError::Path);
            }
            unlinkat(directory, SOCKET_NAME, AtFlags::empty())
                .map_err(|_| DonorIngressError::Io)?;
            fsync(directory).map_err(|_| DonorIngressError::Io)
        }
        Err(Errno::NOENT) => Ok(()),
        Err(_) => Err(DonorIngressError::Path),
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
