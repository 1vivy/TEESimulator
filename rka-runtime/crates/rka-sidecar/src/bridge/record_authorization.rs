use std::{fmt, os::fd::AsFd};

use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags, fstat, openat},
    io::dup,
};

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::{DescriptorSnapshot, ReadBound, read_bounded},
    identity::BrokerIdentity,
    trusted_record::{MAX_RECORD_BYTES, parse_record},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorProperties {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Debug)]
struct DirectoryAnchor {
    descriptor: OwnedFd,
    snapshot: DescriptorSnapshot,
    properties: DescriptorProperties,
}

impl DirectoryAnchor {
    fn capture(descriptor: OwnedFd) -> Result<Self, BridgeError> {
        let (snapshot, stat) = DescriptorSnapshot::trusted(&descriptor)?;
        Ok(Self {
            descriptor,
            snapshot,
            properties: properties(&stat),
        })
    }

    fn verify(&self, deadline: &Deadline) -> Result<(), BridgeError> {
        if !self.snapshot.verify_object(&self.descriptor, deadline)?
            || properties(&fstat(&self.descriptor).map_err(|_| BridgeError::TrustedState)?)
                != self.properties
        {
            return Err(BridgeError::TrustedState);
        }
        deadline.remaining().map(|_| ())
    }
}

#[derive(Debug)]
pub(super) struct RecordPath {
    root: DirectoryAnchor,
    components: Vec<(String, DirectoryAnchor)>,
    name: String,
}

impl RecordPath {
    pub(super) fn new(
        root: OwnedFd,
        components: Vec<(String, OwnedFd)>,
        name: &str,
    ) -> Result<Self, BridgeError> {
        let mut anchors = Vec::new();
        anchors
            .try_reserve(components.len())
            .map_err(|_| BridgeError::Allocation)?;
        for (component, descriptor) in components {
            anchors.push((component, DirectoryAnchor::capture(descriptor)?));
        }
        Ok(Self {
            root: DirectoryAnchor::capture(root)?,
            components: anchors,
            name: name.to_owned(),
        })
    }

    fn open_current_parent(&self, deadline: &Deadline) -> Result<OwnedFd, BridgeError> {
        self.root.verify(deadline)?;
        let mut parent = dup(&self.root.descriptor).map_err(|_| BridgeError::TrustedState)?;
        for (component, expected) in &self.components {
            deadline.remaining()?;
            let current = openat(&parent, component, directory_flags(), Mode::empty())
                .map_err(|_| BridgeError::TrustedState)?;
            let (snapshot, stat) = DescriptorSnapshot::trusted(&current)?;
            if !expected.snapshot.same_object(snapshot) || expected.properties != properties(&stat)
            {
                return Err(BridgeError::TrustedState);
            }
            expected.verify(deadline)?;
            parent = current;
        }
        Ok(parent)
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct RecordRestoreHook {
    pub(super) current: std::path::PathBuf,
    pub(super) original: std::path::PathBuf,
    pub(super) retired_replacement: std::path::PathBuf,
}

#[derive(Debug)]
pub(super) struct OpenRecord {
    pub(super) descriptor: OwnedFd,
    pub(super) snapshot: DescriptorSnapshot,
    pub(super) path: RecordPath,
    #[cfg(test)]
    pub(super) restore_after_read: Option<RecordRestoreHook>,
}

pub(super) struct RecordAuthorization {
    descriptor: OwnedFd,
    snapshot: DescriptorSnapshot,
    properties: DescriptorProperties,
    path: RecordPath,
    bytes: Vec<u8>,
    #[cfg(test)]
    restore_after_read: Option<RecordRestoreHook>,
}

impl RecordAuthorization {
    pub(super) fn new(open: OpenRecord, bytes: Vec<u8>) -> Result<Self, BridgeError> {
        let properties =
            properties(&fstat(&open.descriptor).map_err(|_| BridgeError::TrustedState)?);
        Ok(Self {
            descriptor: open.descriptor,
            snapshot: open.snapshot,
            properties,
            path: open.path,
            bytes,
            #[cfg(test)]
            restore_after_read: open.restore_after_read,
        })
    }

    pub(super) fn revalidate(
        &self,
        identity: &BrokerIdentity,
        deadline: &Deadline,
    ) -> Result<(), BridgeError> {
        if !self.snapshot.verify(&self.descriptor, deadline)? {
            return Err(BridgeError::TrustedState);
        }
        let parent = self.path.open_current_parent(deadline)?;
        let current = open_record(&parent, &self.path.name, deadline)?;
        let (snapshot, stat) = DescriptorSnapshot::trusted(&current)?;
        let mut bytes = read_bounded(
            &current,
            deadline,
            ReadBound {
                bytes: MAX_RECORD_BYTES,
                error: BridgeError::TrustedState,
            },
        )?;
        #[cfg(test)]
        if let Some(hook) = &self.restore_after_read {
            std::fs::rename(&hook.current, &hook.retired_replacement)
                .map_err(|_| BridgeError::TrustedState)?;
            std::fs::rename(&hook.original, &hook.current)
                .map_err(|_| BridgeError::TrustedState)?;
        }
        let after_parent = self.path.open_current_parent(deadline)?;
        let after = open_record(&after_parent, &self.path.name, deadline)?;
        let after_snapshot = DescriptorSnapshot::trusted(&after)?.0;
        let parsed = parse_record(&bytes, identity.role);
        let valid = self.snapshot.same_object(snapshot)
            && self.snapshot.same_object(after_snapshot)
            && self.properties == properties(&stat)
            && bytes == self.bytes
            && parsed.as_ref() == Ok(identity);
        bytes.fill(0);
        if valid {
            Ok(())
        } else {
            Err(BridgeError::TrustedState)
        }
    }
}

impl Drop for RecordAuthorization {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl fmt::Debug for RecordAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordAuthorization")
            .field("record", &"[held]")
            .finish_non_exhaustive()
    }
}

fn open_record(
    parent: &impl AsFd,
    name: &str,
    deadline: &Deadline,
) -> Result<OwnedFd, BridgeError> {
    deadline.remaining()?;
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::TrustedState)
}

const fn properties(stat: &rustix::fs::Stat) -> DescriptorProperties {
    DescriptorProperties {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode & 0o777,
    }
}

const fn directory_flags() -> OFlags {
    OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK)
}
