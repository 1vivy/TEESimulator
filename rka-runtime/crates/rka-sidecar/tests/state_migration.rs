#![allow(missing_docs, reason = "integration tests are behavior-named")]

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use rka_sidecar::candidate::{LegacyCleanup, MigrationStage, cleanup_legacy, migrate_legacy_with};
use rka_sidecar::donor::DonorRuntime;
use rka_state::{StateError, StateStore};

const IDENTITY: [u8; 32] = [4; 32];
const HANDLE: [u8; 32] = [9; 32];

#[test]
fn migration_is_atomic_under_failure_at_every_durable_stage()
-> Result<(), Box<dyn std::error::Error>> {
    for failed_stage in MigrationStage::ALL {
        // Given
        let root = unique_root("atomic");
        write_legacy(&root)?;
        let legacy_path = record_path(&root, b"paired-activation-v1");
        let legacy_before = fs::read(&legacy_path)?;

        // When
        let result = migrate_legacy_with(&root, |stage| {
            if stage == failed_stage {
                Err(std::io::Error::other("injected"))
            } else {
                Ok(())
            }
        });

        // Then
        assert!(result.is_err());
        assert!(!root.join("state-layout-v2").exists());
        assert_eq!(fs::read(&legacy_path)?, legacy_before);
        assert!(!candidate_root(&root).exists());
        migrate_legacy_with(&root, |_| Ok(()))?;
        assert!(root.join("state-layout-v2").is_file());
        assert!(candidate_root(&root).is_dir());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn missing_manifest_keeps_legacy_authoritative() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root("legacy-authority");
    write_legacy(&root)?;

    // When
    let runtime = DonorRuntime::open(&root, Path::new("/unused/broker.sock"));

    // Then
    assert!(runtime.is_active());
    assert!(!root.join("state-layout-v2").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn complete_candidate_directory_without_manifest_is_validated_and_adopted()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root("adopt");
    write_legacy(&root)?;
    migrate_legacy_with(&root, |_| Ok(()))?;
    fs::remove_file(root.join("state-layout-v2"))?;

    // When
    let runtime = DonorRuntime::open(&root, Path::new("/unused/broker.sock"));

    // Then
    assert!(runtime.is_active());
    assert!(root.join("state-layout-v2").is_file());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn after_v2_manifest_commits_a_missing_candidate_directory_fails_closed_and_never_reads_legacy()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root("missing-v2");
    write_legacy(&root)?;
    migrate_legacy_with(&root, |_| Ok(()))?;
    fs::remove_dir_all(candidate_root(&root))?;
    let reads = AtomicUsize::new(0);
    let legacy = CountingStore::new(&root, &reads);

    // When
    let runtime =
        DonorRuntime::open_with_legacy_store(&root, Path::new("/unused/broker.sock"), &legacy);

    // Then
    assert!(!runtime.is_active());
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_records_are_removed_only_after_a_later_successful_startup_and_leave_a_marker()
-> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root("cleanup");
    write_legacy(&root)?;
    let legacy_pair = record_path(&root, b"paired-activation-v1");
    migrate_legacy_with(&root, |_| Ok(()))?;

    // When
    let before_startup = cleanup_legacy(&root, LegacyCleanup::Enabled);
    let runtime = DonorRuntime::open(&root, Path::new("/unused/broker.sock"));
    let disabled = cleanup_legacy(&root, LegacyCleanup::default())?;
    let removed = cleanup_legacy(&root, LegacyCleanup::Enabled)?;

    // Then
    assert!(before_startup.is_err());
    assert!(runtime.is_active());
    assert!(!disabled);
    assert!(removed);
    assert!(!legacy_pair.exists());
    assert!(!record_path(&root, b"rkp-leases-v1").exists());
    assert!(!root.join("donor-transcript-v1").exists());
    assert!(root.join("legacy-cleanup-v2").is_file());
    fs::remove_dir_all(root)?;
    Ok(())
}

fn write_legacy(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let records = root.join("records");
    let chains = root.join("lease-chains");
    fs::create_dir_all(&records)?;
    fs::create_dir_all(&chains)?;
    fs::write(record_path(root, b"paired-activation-v1"), paired_record())?;
    let chain = [0x30, 1, 0, 0x30, 1, 1];
    fs::write(record_path(root, b"rkp-leases-v1"), lease_record(&chain))?;
    fs::write(root.join("donor-transcript-v1"), transcript_record())?;
    fs::write(chains.join(hex(&HANDLE)), chain)?;
    Ok(())
}

fn paired_record() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(237);
    bytes.extend_from_slice(b"RKPA\x01");
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[2; 32]);
    bytes.extend_from_slice(&3_u64.to_be_bytes());
    bytes.extend_from_slice(&IDENTITY);
    bytes.extend_from_slice(&[5; 32]);
    bytes.extend_from_slice(&[6; 32]);
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[8; 32]);
    bytes
}

fn lease_record(chain: &[u8]) -> Vec<u8> {
    let hash = ring::digest::digest(&ring::digest::SHA256, chain);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RKPL\x01");
    bytes.push(1);
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&[2; 16]);
    bytes.push(0);
    bytes.extend_from_slice(&[3; 32]);
    bytes.extend_from_slice(&[4; 32]);
    bytes.extend_from_slice(&[5; 32]);
    bytes.extend_from_slice(&HANDLE);
    bytes.extend_from_slice(hash.as_ref());
    bytes.push(2);
    bytes.extend_from_slice(&[6; 32]);
    bytes.extend_from_slice(&3_u64.to_be_bytes());
    for _ in 0..5 {
        bytes.extend_from_slice(&[8; 32]);
    }
    bytes.push(2);
    bytes
}

fn transcript_record() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(38);
    bytes.extend_from_slice(b"RKDT\x01");
    bytes.push(1);
    bytes.extend_from_slice(&[8; 32]);
    bytes
}

fn record_path(root: &Path, key: &[u8]) -> PathBuf {
    root.join("records").join(hex(key))
}

fn candidate_root(root: &Path) -> PathBuf {
    root.join("candidates").join(hex(&IDENTITY))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

fn unique_root(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rka-state-migration-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

struct CountingStore<'a> {
    records: PathBuf,
    reads: &'a AtomicUsize,
}

impl<'a> CountingStore<'a> {
    fn new(root: &Path, reads: &'a AtomicUsize) -> Self {
        Self {
            records: root.join("records"),
            reads,
        }
    }
}

impl StateStore for CountingStore<'_> {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        if key == b"paired-activation-v1" {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        let value = fs::read(self.records.join(hex(key))).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StateError::Missing
            } else {
                StateError::Storage
            }
        })?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(StateError::Storage)
    }
}
