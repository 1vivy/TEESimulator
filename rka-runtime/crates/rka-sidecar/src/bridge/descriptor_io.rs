use std::os::fd::AsFd;

use rustix::{
    event::PollFlags,
    fs::{Stat, fstat},
    io::{Errno, read},
};

use super::{BridgeError, deadline::Deadline};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DescriptorSnapshot {
    device: u64,
    inode: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i128,
}

impl DescriptorSnapshot {
    pub(super) fn capture(descriptor: &impl AsFd) -> Result<Self, BridgeError> {
        Ok(Self::from_stat(
            fstat(descriptor).map_err(|_| BridgeError::PeerIdentity)?,
        ))
    }

    pub(super) fn trusted(descriptor: &impl AsFd) -> Result<(Self, Stat), BridgeError> {
        let stat = fstat(descriptor).map_err(|_| BridgeError::TrustedState)?;
        Ok((Self::from_stat(stat), stat))
    }

    pub(super) fn verify(
        self,
        descriptor: &impl AsFd,
        deadline: &Deadline,
    ) -> Result<bool, BridgeError> {
        deadline.remaining()?;
        let current = fstat(descriptor).ok();
        deadline.remaining()?;
        Ok(current.is_some_and(|stat| Self::from_stat(stat) == self))
    }

    pub(super) const fn device(self) -> u64 {
        self.device
    }

    pub(super) const fn inode(self) -> u64 {
        self.inode
    }

    fn from_stat(stat: Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: i128::from(stat.st_mtime_nsec),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReadBound {
    pub(super) bytes: usize,
    pub(super) error: BridgeError,
}

pub(super) fn read_bounded(
    descriptor: &impl AsFd,
    deadline: &Deadline,
    bound: ReadBound,
) -> Result<Vec<u8>, BridgeError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve(bound.bytes)
        .map_err(|_| BridgeError::Allocation)?;
    let mut chunk = [0_u8; 512];
    loop {
        deadline.wait(descriptor, PollFlags::IN)?;
        match read(descriptor, &mut chunk) {
            Ok(0) => return Ok(bytes),
            Ok(count) => {
                let next = bytes.len().checked_add(count).ok_or(bound.error)?;
                if next > bound.bytes {
                    bytes.fill(0);
                    return Err(bound.error);
                }
                bytes.extend_from_slice(chunk.get(..count).ok_or(bound.error)?);
            }
            Err(Errno::AGAIN) => {}
            Err(_) => {
                bytes.fill(0);
                return Err(bound.error);
            }
        }
    }
}
