use crate::StateError;
use rustix::{
    fs::{CWD, FileType, Mode, OFlags, fstat, fsync, mkdirat, openat},
    io::Errno,
};
use std::{fs::File, io::Write, os::fd::OwnedFd};

#[cfg(test)]
use std::path::Path;

const RECEIPT_ROOT: &str = "/data/adb/teesimulator-rka/journal/validated-receipts";
const PARENT_COMPONENTS: [&str; 4] = ["data", "adb", "teesimulator-rka", "journal"];
const LEAF: &str = "validated-receipts";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Root-owned, descriptor-anchored registry for consumed validator receipts.
#[derive(Debug)]
pub struct ValidatedReceiptRegistry {
    root: OwnedFd,
    owner: Ownership,
}

#[derive(Clone, Copy, Debug)]
struct Ownership {
    uid: u32,
    gid: u32,
}

impl ValidatedReceiptRegistry {
    /// Opens the fixed root-owned durable receipt-consumption registry.
    ///
    /// # Errors
    /// Fails closed unless every existing component is a root-owned, private,
    /// non-symlink directory. Only the final registry directory may be created.
    pub fn open() -> Result<Self, StateError> {
        debug_assert_eq!(
            format!("/{}/{}", PARENT_COMPONENTS.join("/"), LEAF),
            RECEIPT_ROOT
        );
        let anchor = openat(CWD, "/", directory_flags(), Mode::empty()).map_err(storage_error)?;
        Self::open_beneath(anchor, Ownership { uid: 0, gid: 0 })
    }

    #[cfg(test)]
    pub(crate) fn for_test(anchor: &Path) -> Result<Self, StateError> {
        let anchor =
            openat(CWD, anchor, directory_flags(), Mode::empty()).map_err(storage_error)?;
        let stat = fstat(&anchor).map_err(storage_error)?;
        Self::open_beneath(
            anchor,
            Ownership {
                uid: stat.st_uid,
                gid: stat.st_gid,
            },
        )
    }

    fn open_beneath(mut parent: OwnedFd, owner: Ownership) -> Result<Self, StateError> {
        for component in PARENT_COMPONENTS {
            let directory = openat(&parent, component, directory_flags(), Mode::empty())
                .map_err(storage_error)?;
            validate_directory(&directory, owner)?;
            parent = directory;
        }
        match mkdirat(&parent, LEAF, Mode::from_raw_mode(DIRECTORY_MODE)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(storage_error(error)),
        }
        let root =
            openat(&parent, LEAF, directory_flags(), Mode::empty()).map_err(storage_error)?;
        validate_directory(&root, owner)?;
        fsync(&parent).map_err(storage_error)?;
        Ok(Self { root, owner })
    }

    pub(crate) fn consume_once(&self, receipt_identity: &[u8; 32]) -> Result<bool, StateError> {
        let descriptor = match openat(
            &self.root,
            hex(receipt_identity)?,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(FILE_MODE),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::EXIST) => return Ok(false),
            Err(error) => return Err(storage_error(error)),
        };
        let before = validate_file(&descriptor, self.owner)?;
        let mut file = File::from(descriptor);
        file.write_all(receipt_identity).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        let after = validate_file(&file, self.owner)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(StateError::Storage);
        }
        fsync(&self.root).map_err(storage_error)?;
        Ok(true)
    }
}

fn validate_directory(descriptor: &OwnedFd, owner: Ownership) -> Result<(), StateError> {
    let stat = fstat(descriptor).map_err(storage_error)?;
    if stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o777 != DIRECTORY_MODE
        || !FileType::from_raw_mode(stat.st_mode).is_dir()
    {
        return Err(StateError::Storage);
    }
    Ok(())
}

fn validate_file<Fd: std::os::fd::AsFd>(
    descriptor: Fd,
    owner: Ownership,
) -> Result<rustix::fs::Stat, StateError> {
    let stat = fstat(descriptor).map_err(storage_error)?;
    if stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o777 != FILE_MODE
        || !FileType::from_raw_mode(stat.st_mode).is_file()
    {
        return Err(StateError::Storage);
    }
    Ok(stat)
}

const fn directory_flags() -> OFlags {
    OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK)
}

fn hex(bytes: &[u8]) -> Result<String, StateError> {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from_digit(u32::from(byte >> 4), 16).ok_or(StateError::Storage)?);
        encoded.push(char::from_digit(u32::from(byte & 0x0f), 16).ok_or(StateError::Storage)?);
    }
    Ok(encoded)
}

fn storage_error<T>(_: T) -> StateError {
    StateError::Storage
}

#[cfg(test)]
#[path = "rkp_receipt_registry_tests.rs"]
mod tests;
