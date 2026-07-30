use std::sync::Arc;

use rustix::{
    fs::{AtFlags, CWD, Mode, OFlags, fstat, openat, statat},
    io::read,
};

use super::{
    BridgeError,
    identity::{BROKER_EXECUTABLE, BrokerIdentity, BrokerRole},
};

const RECORD_COMPONENTS: [&str; 5] = ["data", "adb", "teesimulator-rka", "run", "pids"];
const RECORD_NAME: &str = "broker.identity";
const MAX_RECORD_BYTES: usize = 4096;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

pub(super) fn read_identity_record(role: BrokerRole) -> Result<BrokerIdentity, BridgeError> {
    let root = openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::TrustedState)?;
    let mut parent = Arc::new(root);
    for component in RECORD_COMPONENTS {
        let descriptor = openat(
            parent.as_ref(),
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BridgeError::TrustedState)?;
        let stat = fstat(&descriptor).map_err(|_| BridgeError::TrustedState)?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o777 != DIRECTORY_MODE {
            return Err(BridgeError::TrustedState);
        }
        parent = Arc::new(descriptor);
    }
    let descriptor = openat(
        parent.as_ref(),
        RECORD_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::TrustedState)?;
    let before = fstat(&descriptor).map_err(|_| BridgeError::TrustedState)?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o777 != FILE_MODE
        || before.st_size <= 0
        || usize::try_from(before.st_size).map_err(|_| BridgeError::TrustedState)?
            > MAX_RECORD_BYTES
    {
        return Err(BridgeError::TrustedState);
    }
    let size = usize::try_from(before.st_size).map_err(|_| BridgeError::TrustedState)?;
    let mut bytes = vec![0_u8; size];
    let mut offset = 0;
    while offset < size {
        let target = bytes.get_mut(offset..).ok_or(BridgeError::TrustedState)?;
        let count = read(&descriptor, target).map_err(|_| BridgeError::TrustedState)?;
        if count == 0 {
            return Err(BridgeError::TrustedState);
        }
        offset = offset.checked_add(count).ok_or(BridgeError::TrustedState)?;
    }
    let after = fstat(&descriptor).map_err(|_| BridgeError::TrustedState)?;
    let named = statat(parent.as_ref(), RECORD_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BridgeError::TrustedState)?;
    if before.st_ino != after.st_ino
        || before.st_ino != named.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
    {
        bytes.fill(0);
        return Err(BridgeError::TrustedState);
    }
    let parsed = parse_record(&bytes, role);
    bytes.fill(0);
    parsed
}

fn parse_record(bytes: &[u8], role: BrokerRole) -> Result<BrokerIdentity, BridgeError> {
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
}
