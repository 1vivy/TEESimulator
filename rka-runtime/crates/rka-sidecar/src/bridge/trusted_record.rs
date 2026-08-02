use std::os::fd::AsFd;

use rustix::{
    fd::OwnedFd,
    fs::{CWD, Mode, OFlags, fstat, openat},
    io::dup,
};

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::DescriptorSnapshot,
    identity::{BROKER_EXECUTABLE, BrokerIdentity, BrokerRole},
    record_authorization::{OpenRecord, RecordPath},
};

const RECORD_NAME: &str = "broker.identity";
pub(super) const MAX_RECORD_BYTES: usize = 4096;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy)]
struct DirectoryPolicy {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Copy)]
struct DirectoryProperties {
    uid: u32,
    gid: u32,
    mode: u32,
}

impl DirectoryPolicy {
    const ANDROID_DATA: Self = Self {
        uid: 1000,
        gid: 1000,
        mode: 0o771,
    };

    const ROOT_PRIVATE: Self = Self {
        uid: 0,
        gid: 0,
        mode: DIRECTORY_MODE,
    };

    const fn accepts(self, properties: DirectoryProperties) -> bool {
        self.uid == properties.uid && self.gid == properties.gid && self.mode == properties.mode
    }
}

const fn directory_properties(uid: u32, gid: u32, mode: u32) -> DirectoryProperties {
    DirectoryProperties { uid, gid, mode }
}

#[derive(Clone, Copy)]
struct RecordComponent {
    name: &'static str,
    policy: DirectoryPolicy,
}

const RECORD_COMPONENTS: [RecordComponent; 5] = [
    RecordComponent {
        name: "data",
        policy: DirectoryPolicy::ANDROID_DATA,
    },
    RecordComponent {
        name: "adb",
        policy: DirectoryPolicy::ROOT_PRIVATE,
    },
    RecordComponent {
        name: "teesimulator-rka",
        policy: DirectoryPolicy::ROOT_PRIVATE,
    },
    RecordComponent {
        name: "run",
        policy: DirectoryPolicy::ROOT_PRIVATE,
    },
    RecordComponent {
        name: "pids",
        policy: DirectoryPolicy::ROOT_PRIVATE,
    },
];

pub(super) fn open_identity_record(deadline: &Deadline) -> Result<OpenRecord, BridgeError> {
    deadline.remaining()?;
    let root = openat(CWD, "/", directory_flags(), Mode::empty())
        .map_err(|_| BridgeError::TrustedState)?;
    let root_anchor = dup(&root).map_err(|_| BridgeError::TrustedState)?;
    let mut parent = root;
    let mut components = Vec::new();
    components
        .try_reserve(RECORD_COMPONENTS.len())
        .map_err(|_| BridgeError::Allocation)?;
    for component in RECORD_COMPONENTS {
        deadline.remaining()?;
        let descriptor = open_trusted_directory(&parent, component)?;
        components.push((
            component.name.to_owned(),
            dup(&descriptor).map_err(|_| BridgeError::TrustedState)?,
        ));
        parent = descriptor;
    }
    deadline.remaining()?;
    let descriptor = openat(
        &parent,
        RECORD_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::TrustedState)?;
    let (snapshot, before) = DescriptorSnapshot::trusted(&descriptor)?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o777 != FILE_MODE
        || before.st_size <= 0
        || usize::try_from(before.st_size).map_err(|_| BridgeError::TrustedState)?
            > MAX_RECORD_BYTES
    {
        return Err(BridgeError::TrustedState);
    }
    deadline.remaining()?;
    Ok(OpenRecord {
        descriptor,
        snapshot,
        path: RecordPath::new(root_anchor, components, RECORD_NAME)?,
        #[cfg(test)]
        restore_after_read: None,
    })
}

fn open_trusted_directory(
    parent: &impl AsFd,
    component: RecordComponent,
) -> Result<OwnedFd, BridgeError> {
    let descriptor = openat(parent, component.name, directory_flags(), Mode::empty())
        .map_err(|_| BridgeError::TrustedState)?;
    let stat = fstat(&descriptor).map_err(|_| BridgeError::TrustedState)?;
    if component.policy.accepts(directory_properties(
        stat.st_uid,
        stat.st_gid,
        stat.st_mode & 0o777,
    )) {
        Ok(descriptor)
    } else {
        Err(BridgeError::TrustedState)
    }
}

const fn directory_flags() -> OFlags {
    OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK)
}

pub(super) fn parse_record(bytes: &[u8], role: BrokerRole) -> Result<BrokerIdentity, BridgeError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(BridgeError::TrustedState);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BridgeError::TrustedState)?;
    if !text.ends_with('\n') {
        return Err(BridgeError::TrustedState);
    }
    let mut values = text.lines();
    let version = field(&mut values, "version")?;
    let generation = field(&mut values, "generation")?;
    let launch_nonce = field(&mut values, "launch_nonce")?;
    let uid = field(&mut values, "uid")?;
    let gid = field(&mut values, "gid")?;
    let pid = field(&mut values, "pid")?;
    let start = field(&mut values, "start_time_ticks")?;
    let inode = field(&mut values, "executable_inode")?;
    let executable = field(&mut values, "executable_path")?;
    let recorded_role = field(&mut values, "role")?;
    if values.next().is_some()
        || version != "1"
        || launch_nonce.len() != 64
        || !launch_nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || executable != BROKER_EXECUTABLE
        || recorded_role != role.record()
    {
        return Err(BridgeError::TrustedState);
    }
    Ok(BrokerIdentity {
        generation: parse_number(generation)?,
        launch_nonce: launch_nonce.to_owned(),
        uid: parse_root(uid)?,
        gid: parse_root(gid)?,
        pid: pid
            .parse::<i32>()
            .map_err(|_| BridgeError::TrustedState)?
            .checked_abs()
            .filter(|value| *value > 0)
            .ok_or(BridgeError::TrustedState)?,
        start_time_ticks: parse_number(start)?,
        executable_inode: parse_number(inode)?,
        role,
    })
}

fn field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<&'a str, BridgeError> {
    let line = lines.next().ok_or(BridgeError::TrustedState)?;
    let (key, value) = line.split_once('=').ok_or(BridgeError::TrustedState)?;
    if key != expected || value.is_empty() {
        return Err(BridgeError::TrustedState);
    }
    Ok(value)
}

fn parse_number(value: &str) -> Result<u64, BridgeError> {
    value.parse().map_err(|_| BridgeError::TrustedState)
}

fn parse_root(value: &str) -> Result<u32, BridgeError> {
    let parsed = value.parse().map_err(|_| BridgeError::TrustedState)?;
    if parsed == 0 {
        Ok(parsed)
    } else {
        Err(BridgeError::TrustedState)
    }
}

#[cfg(test)]
#[path = "trusted_record_tests.rs"]
mod tests;
