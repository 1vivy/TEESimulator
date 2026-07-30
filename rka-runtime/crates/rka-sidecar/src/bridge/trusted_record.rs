use rustix::{
    fd::OwnedFd,
    fs::{CWD, Mode, OFlags, fstat, openat},
};

use super::{
    BridgeError,
    deadline::Deadline,
    descriptor_io::DescriptorSnapshot,
    identity::{BROKER_EXECUTABLE, BrokerIdentity, BrokerRole},
};

const RECORD_COMPONENTS: [&str; 5] = ["data", "adb", "teesimulator-rka", "run", "pids"];
const RECORD_NAME: &str = "broker.identity";
pub(super) const MAX_RECORD_BYTES: usize = 4096;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub(super) struct OpenRecord {
    pub(super) descriptor: OwnedFd,
    pub(super) snapshot: DescriptorSnapshot,
}

pub(super) fn open_identity_record(deadline: &Deadline) -> Result<OpenRecord, BridgeError> {
    deadline.remaining()?;
    let root = openat(CWD, "/", directory_flags(), Mode::empty())
        .map_err(|_| BridgeError::TrustedState)?;
    let mut parent = root;
    for component in RECORD_COMPONENTS {
        deadline.remaining()?;
        let descriptor = openat(&parent, component, directory_flags(), Mode::empty())
            .map_err(|_| BridgeError::TrustedState)?;
        let stat = fstat(&descriptor).map_err(|_| BridgeError::TrustedState)?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o777 != DIRECTORY_MODE {
            return Err(BridgeError::TrustedState);
        }
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
    })
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
mod tests {
    use super::*;

    fn record(role: &str) -> Vec<u8> {
        format!(
            "version=1\ngeneration=7\nlaunch_nonce={}\nuid=0\ngid=0\npid=42\nstart_time_ticks=99\nexecutable_inode=123\nexecutable_path={BROKER_EXECUTABLE}\nrole={role}\n",
            "01".repeat(32)
        )
        .into_bytes()
    }

    #[test]
    fn bridge_identity_record_accepts_exact_closed_schema() {
        let parsed = parse_record(&record("DONOR"), BrokerRole::Donor);
        assert!(parsed.is_ok_and(|identity| {
            identity.generation == 7
                && identity.pid == 42
                && identity.start_time_ticks == 99
                && identity.executable_inode == 123
        }));
    }

    #[test]
    fn bridge_identity_record_rejects_role_and_pid_reuse_fields() {
        assert_eq!(
            parse_record(&record("CANDIDATE"), BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
        let invalid_pid = String::from_utf8_lossy(&record("DONOR")).replace("pid=42", "pid=0");
        assert_eq!(
            parse_record(invalid_pid.as_bytes(), BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
    }

    #[test]
    fn bridge_identity_record_rejects_nonce_executable_and_trailing_fields() {
        let uppercase = String::from_utf8_lossy(&record("DONOR")).replace("01", "AB");
        assert_eq!(
            parse_record(uppercase.as_bytes(), BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
        let executable =
            String::from_utf8_lossy(&record("DONOR")).replace(BROKER_EXECUTABLE, "/system/bin/sh");
        assert_eq!(
            parse_record(executable.as_bytes(), BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
        let mut trailing = record("DONOR");
        trailing.extend_from_slice(b"extra=1\n");
        assert_eq!(
            parse_record(&trailing, BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
    }

    #[test]
    fn bridge_identity_record_rejects_partial_oversize_and_invalid_utf8() {
        let mut partial = record("DONOR");
        partial.truncate(32);
        assert_eq!(
            parse_record(&partial, BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
        let mut oversized = record("DONOR");
        oversized.resize(MAX_RECORD_BYTES + 1, b'x');
        assert_eq!(
            parse_record(&oversized, BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
        assert_eq!(
            parse_record(&[0xff, b'\n'], BrokerRole::Donor),
            Err(BridgeError::TrustedState)
        );
    }
}
