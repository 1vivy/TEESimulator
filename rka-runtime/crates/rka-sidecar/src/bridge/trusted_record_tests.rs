use std::{
    fs::{self, File},
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rka-trusted-record-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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
fn bridge_identity_path_accepts_android_data_then_private_state() {
    // Given
    let android_data = RECORD_COMPONENTS[0];
    let protected_state = &RECORD_COMPONENTS[1..];

    // When
    let data_is_valid = android_data
        .policy
        .accepts(directory_properties(1000, 1000, 0o771));
    let protected_is_valid = protected_state.iter().all(|component| {
        component
            .policy
            .accepts(directory_properties(0, 0, DIRECTORY_MODE))
    });

    // Then
    assert!(data_is_valid);
    assert!(protected_is_valid);
    assert!(
        !android_data
            .policy
            .accepts(directory_properties(0, 0, DIRECTORY_MODE))
    );
    assert!(protected_state.iter().all(|component| {
        !component
            .policy
            .accepts(directory_properties(1000, 1000, 0o771))
    }));
}

#[test]
fn bridge_identity_path_rejects_writable_or_wrong_owner_protected_state() {
    // Given
    let protected_state = &RECORD_COMPONENTS[1..];

    // When
    let writable = protected_state
        .iter()
        .all(|component| !component.policy.accepts(directory_properties(0, 0, 0o702)));
    let wrong_owner = [
        directory_properties(1000, 0, DIRECTORY_MODE),
        directory_properties(0, 1000, DIRECTORY_MODE),
    ];
    let owner_rejected = protected_state.iter().all(|component| {
        wrong_owner
            .iter()
            .all(|properties| !component.policy.accepts(*properties))
    });

    // Then
    assert!(writable);
    assert!(owner_rejected);
}

#[test]
fn bridge_identity_path_rejects_a_symlinked_protected_component()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = TempDirectory::new()?;
    let target = root.0.join("replacement");
    fs::create_dir(&target)?;
    symlink(&target, root.0.join("pids"))?;
    let root_descriptor = File::open(&root.0)?;

    // When
    let result = open_trusted_directory(&root_descriptor, RECORD_COMPONENTS[4]);

    // Then
    assert!(matches!(result, Err(BridgeError::TrustedState)));
    Ok(())
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
