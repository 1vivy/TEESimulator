use std::{
    fs::{self, File},
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fd::OwnedFd;

use super::{
    BridgeError, BrokerRole,
    descriptor_io::DescriptorSnapshot,
    identity::{BROKER_EXECUTABLE, PeerCredentials},
    identity_source::{ProcessDescriptors, TestIdentitySource},
    process_liveness::ProcessLiveness,
    record_authorization::{OpenRecord, RecordPath},
};

static NEXT_SOURCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn ready_source(role: BrokerRole) -> Result<TestIdentitySource, BridgeError> {
    let root = std::env::temp_dir().join(format!(
        "rka-role-executor-identity-{}-{}",
        std::process::id(),
        NEXT_SOURCE.fetch_add(1, Ordering::Relaxed)
    ));
    create_source(&root, role).map(|source| source.with_cleanup_root(root))
}

fn create_source(root: &PathBuf, role: BrokerRole) -> Result<TestIdentitySource, BridgeError> {
    fs::create_dir(root).map_err(|_| BridgeError::TrustedState)?;
    let proc_root = root.join("proc");
    let process_name = std::process::id().to_string();
    let process = proc_root.join(&process_name);
    fs::create_dir(&proc_root).map_err(|_| BridgeError::TrustedState)?;
    fs::create_dir(&process).map_err(|_| BridgeError::TrustedState)?;

    let executable_path = root.join("app_process64");
    fs::write(&executable_path, b"test executable").map_err(|_| BridgeError::TrustedState)?;
    let executable =
        OwnedFd::from(File::open(&executable_path).map_err(|_| BridgeError::TrustedState)?);
    let executable_inode = DescriptorSnapshot::capture(&executable)?.inode();
    symlink(&executable_path, process.join("exe")).map_err(|_| BridgeError::TrustedState)?;

    let credentials = PeerCredentials {
        uid: 0,
        gid: 0,
        pid: i32::try_from(std::process::id()).map_err(|_| BridgeError::PeerIdentity)?,
    };
    let record_parent = root.join("trusted");
    fs::create_dir(&record_parent).map_err(|_| BridgeError::TrustedState)?;
    let record_path = record_parent.join("record");
    let record = format!(
        "version=1\ngeneration=7\nlaunch_nonce={}\nuid={}\ngid={}\npid={}\nstart_time_ticks=99\nexecutable_inode={}\nexecutable_path={}\nrole={}\n",
        "01".repeat(32),
        credentials.uid,
        credentials.gid,
        credentials.pid,
        executable_inode,
        BROKER_EXECUTABLE,
        role.record()
    );
    fs::write(&record_path, record).map_err(|_| BridgeError::TrustedState)?;
    fs::write(
        process.join("stat"),
        b"42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99",
    )
    .map_err(|_| BridgeError::PeerIdentity)?;
    fs::write(
        process.join("cmdline"),
        format!(
            "{BROKER_EXECUTABLE}\0/system/bin\0org.matrix.TEESimulator.App\0--rka-role\0{}\0",
            role.argument()
        ),
    )
    .map_err(|_| BridgeError::PeerIdentity)?;

    let record_descriptor =
        OwnedFd::from(File::open(&record_path).map_err(|_| BridgeError::TrustedState)?);
    let record_snapshot = DescriptorSnapshot::capture(&record_descriptor)?;
    let record_path = RecordPath::new(
        OwnedFd::from(File::open(root).map_err(|_| BridgeError::TrustedState)?),
        vec![(
            "trusted".to_owned(),
            OwnedFd::from(File::open(&record_parent).map_err(|_| BridgeError::TrustedState)?),
        )],
        "record",
    )?;
    let process_descriptors = ProcessDescriptors {
        liveness: ProcessLiveness::ProcDirectory,
        proc_root: OwnedFd::from(File::open(&proc_root).map_err(|_| BridgeError::PeerIdentity)?),
        process_name,
        directory: OwnedFd::from(File::open(&process).map_err(|_| BridgeError::PeerIdentity)?),
        stat: OwnedFd::from(
            File::open(process.join("stat")).map_err(|_| BridgeError::PeerIdentity)?,
        ),
        cmdline: OwnedFd::from(
            File::open(process.join("cmdline")).map_err(|_| BridgeError::PeerIdentity)?,
        ),
        executable,
        expected_executable: OwnedFd::from(
            File::open(&executable_path).map_err(|_| BridgeError::PeerIdentity)?,
        ),
        revalidation_gate: None,
    };
    Ok(TestIdentitySource::new(
        OpenRecord {
            descriptor: record_descriptor,
            snapshot: record_snapshot,
            path: record_path,
            restore_after_read: None,
        },
        process_descriptors,
    ))
}
