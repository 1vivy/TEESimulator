use std::{
    fs::{self, File, FileTimes, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::symlink,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use rustix::{
    fd::OwnedFd,
    process::{Pid, PidfdFlags, pidfd_open},
};

use super::{
    BridgeError, BrokerRole,
    deadline::{Control, Deadline},
    descriptor_io::DescriptorSnapshot,
    identity::{AuthenticationRequest, BROKER_EXECUTABLE, authenticate_with_source},
    identity_source::{ProcessDescriptors, TestIdentitySource},
    peer_authorization::PeerAuthorization,
    process_identity::{parse_cmdline, parse_start_time},
    process_liveness::ProcessLiveness,
    trusted_record::OpenRecord,
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rka-identity-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Ready,
    Record,
    Stat,
    Cmdline,
    Preexposure,
    ExecutableMismatch,
}

struct Fixture {
    source: TestIdentitySource,
    _writer: Option<UnixStream>,
    _tree: TempTree,
    record_path: PathBuf,
    executable_path: PathBuf,
    process_path: PathBuf,
    stat_path: PathBuf,
    cmdline_path: PathBuf,
    executable_link: PathBuf,
}

fn deadline(duration: Duration) -> Result<Deadline, BridgeError> {
    Deadline::new(duration, Control::new()?)
}

fn authenticate(
    source: &mut TestIdentitySource,
    stream: &UnixStream,
    deadline: &Deadline,
) -> Result<PeerAuthorization, BridgeError> {
    authenticate_with_source(
        source,
        AuthenticationRequest {
            stream,
            role: BrokerRole::Donor,
            deadline,
        },
    )
}

fn stalled() -> Result<(OwnedFd, UnixStream), Box<dyn std::error::Error>> {
    let (reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    Ok((OwnedFd::from(reader), writer))
}

fn test_liveness(proc_liveness: bool) -> Result<ProcessLiveness, Box<dyn std::error::Error>> {
    if proc_liveness {
        Ok(ProcessLiveness::ProcDirectory)
    } else {
        let pid = Pid::from_raw(i32::try_from(std::process::id())?)
            .ok_or("current process id was zero")?;
        Ok(ProcessLiveness::Pidfd(pidfd_open(
            pid,
            PidfdFlags::NONBLOCK,
        )?))
    }
}

fn rewrite_preserving_snapshot(
    path: &PathBuf,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() != u64::try_from(bytes.len())? {
        return Err("replacement must preserve file size".into());
    }
    let times = FileTimes::new()
        .set_accessed(metadata.accessed()?)
        .set_modified(metadata.modified()?);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_times(times)?;
    Ok(())
}

fn fixture(phase: Phase) -> Result<Fixture, Box<dyn std::error::Error>> {
    fixture_with_proc_liveness(phase, false)
}

fn fixture_with_proc_liveness(
    phase: Phase,
    proc_liveness: bool,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let tree = TempTree::new("proc")?;
    let proc_path = tree.0.join("proc");
    let process_name = std::process::id().to_string();
    let process_path = proc_path.join(&process_name);
    fs::create_dir(&proc_path)?;
    fs::create_dir(&process_path)?;
    let executable_path = tree.0.join("app_process64");
    fs::write(&executable_path, b"executable")?;
    let executable = OwnedFd::from(File::open(&executable_path)?);
    let executable_inode = DescriptorSnapshot::capture(&executable)?.inode();
    let expected_path = tree.0.join("other");
    fs::write(&expected_path, b"other")?;
    let expected_executable = if matches!(phase, Phase::ExecutableMismatch) {
        OwnedFd::from(File::open(&expected_path)?)
    } else {
        OwnedFd::from(File::open(&executable_path)?)
    };
    let executable_link = process_path.join("exe");
    symlink(&executable_path, &executable_link)?;
    let record = format!(
        "version=1\ngeneration=7\nlaunch_nonce={}\nuid={}\ngid={}\npid={}\nstart_time_ticks=99\nexecutable_inode={executable_inode}\nexecutable_path={BROKER_EXECUTABLE}\nrole=DONOR\n",
        "01".repeat(32),
        0,
        0,
        std::process::id()
    );
    let record_path = tree.0.join("record");
    fs::write(&record_path, record.as_bytes())?;
    let stat_path = process_path.join("stat");
    fs::write(
        &stat_path,
        b"42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99",
    )?;
    let cmdline_path = process_path.join("cmdline");
    fs::write(
        &cmdline_path,
        b"/system/bin/app_process64\0/system/bin\0org.matrix.TEESimulator.App\0--rka-role\0donor\0",
    )?;
    let mut writer = None;
    let record_descriptor = if matches!(phase, Phase::Record) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        OwnedFd::from(File::open(&record_path)?)
    };
    let stat = if matches!(phase, Phase::Stat) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        OwnedFd::from(File::open(&stat_path)?)
    };
    let cmdline = if matches!(phase, Phase::Cmdline) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        OwnedFd::from(File::open(&cmdline_path)?)
    };
    let revalidation_gate = if matches!(phase, Phase::Preexposure) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        Some(reader)
    } else {
        None
    };
    let record_snapshot = DescriptorSnapshot::capture(&record_descriptor)?;
    let process = ProcessDescriptors {
        liveness: test_liveness(proc_liveness)?,
        proc_root: OwnedFd::from(File::open(&proc_path)?),
        process_name,
        directory: OwnedFd::from(File::open(&process_path)?),
        stat,
        cmdline,
        executable,
        expected_executable,
        revalidation_gate,
    };
    Ok(Fixture {
        source: TestIdentitySource::new(
            OpenRecord {
                descriptor: record_descriptor,
                snapshot: record_snapshot,
            },
            process,
        ),
        _writer: writer,
        _tree: tree,
        record_path,
        executable_path,
        process_path,
        stat_path,
        cmdline_path,
        executable_link,
    })
}

#[test]
fn bridge_procfs_parser_handles_parentheses_and_exact_start_time() {
    let stat = b"42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99";
    assert_eq!(parse_start_time(stat), Ok(99));
}

#[test]
fn bridge_procfs_cmdline_rejects_empty_unterminated_and_empty_argument() {
    assert_eq!(parse_cmdline(b""), Err(BridgeError::PeerIdentity));
    assert_eq!(parse_cmdline(b"broker"), Err(BridgeError::PeerIdentity));
    assert_eq!(
        parse_cmdline(b"broker\0\0role\0"),
        Err(BridgeError::PeerIdentity)
    );
}

#[test]
fn blocked_identity_fields_use_one_absolute_deadline() -> Result<(), Box<dyn std::error::Error>> {
    for phase in [Phase::Record, Phase::Stat, Phase::Cmdline] {
        let mut fixture = fixture(phase)?;
        let (stream, _peer) = UnixStream::pair()?;
        let started = Instant::now();
        assert!(matches!(
            authenticate(
                &mut fixture.source,
                &stream,
                &deadline(Duration::from_millis(20))?,
            ),
            Err(BridgeError::Deadline)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    Ok(())
}

#[test]
fn blocked_preexposure_revalidation_uses_original_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(Phase::Preexposure)?;
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(20))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    let started = Instant::now();
    assert_eq!(
        authorization.revalidate(&stream, &deadline),
        Err(BridgeError::Deadline)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn close_cancels_every_blocked_identity_field() -> Result<(), Box<dyn std::error::Error>> {
    for phase in [Phase::Record, Phase::Stat, Phase::Cmdline] {
        let mut fixture = fixture(phase)?;
        let (stream, _peer) = UnixStream::pair()?;
        let control = Control::new()?;
        control.close();
        let deadline = Deadline::new(Duration::from_secs(1), control)?;
        assert!(matches!(
            authenticate(&mut fixture.source, &stream, &deadline),
            Err(BridgeError::PeerDied)
        ));
    }
    Ok(())
}

#[test]
fn held_executable_requires_same_device_and_inode() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(Phase::ExecutableMismatch)?;
    let (stream, _peer) = UnixStream::pair()?;
    assert!(matches!(
        authenticate(
            &mut fixture.source,
            &stream,
            &deadline(Duration::from_millis(100))?,
        ),
        Err(BridgeError::PeerIdentity)
    ));
    Ok(())
}

#[test]
fn held_descriptors_detect_preexposure_content_change() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(Phase::Ready)?;
    let executable_path = fixture.executable_path.clone();
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(100))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    fs::write(executable_path, b"changed executable content")?;
    assert_eq!(
        authorization.revalidate(&stream, &deadline),
        Err(BridgeError::PeerIdentity)
    );
    Ok(())
}

#[test]
fn record_name_swap_cannot_redirect_held_authorization() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(Phase::Ready)?;
    let record_path = fixture.record_path.clone();
    let old_path = record_path.with_extension("held");
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(100))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    fs::rename(&record_path, &old_path)?;
    fs::write(&record_path, b"attacker-controlled replacement")?;
    assert_eq!(authorization.revalidate(&stream, &deadline), Ok(()));
    Ok(())
}

#[test]
fn proc_directory_strategy_authenticates_valid_peer() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_with_proc_liveness(Phase::Ready, true)?;
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(250))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    assert_eq!(authorization.revalidate(&stream, &deadline), Ok(()));
    Ok(())
}

#[test]
fn proc_directory_strategy_rejects_exit_and_pid_reuse() -> Result<(), Box<dyn std::error::Error>> {
    for replace in [false, true] {
        let mut fixture = fixture_with_proc_liveness(Phase::Ready, true)?;
        let (stream, _peer) = UnixStream::pair()?;
        let deadline = deadline(Duration::from_millis(250))?;
        let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
        let retired = fixture.process_path.with_extension("retired");
        fs::rename(&fixture.process_path, &retired)?;
        if replace {
            fs::create_dir(&fixture.process_path)?;
        }
        assert!(matches!(
            authorization.revalidate(&stream, &deadline),
            Err(BridgeError::PeerDied | BridgeError::PeerIdentity)
        ));
    }
    Ok(())
}

#[test]
fn proc_directory_strategy_rejects_exec_change() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_with_proc_liveness(Phase::Ready, true)?;
    let replacement = fixture.executable_path.with_extension("replacement");
    fs::write(&replacement, b"replacement")?;
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(250))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    fs::remove_file(&fixture.executable_link)?;
    symlink(replacement, &fixture.executable_link)?;
    assert_eq!(
        authorization.revalidate(&stream, &deadline),
        Err(BridgeError::PeerIdentity)
    );
    Ok(())
}

#[test]
fn proc_directory_strategy_rejects_start_and_cmdline_change()
-> Result<(), Box<dyn std::error::Error>> {
    for stat_change in [true, false] {
        let mut fixture = fixture_with_proc_liveness(Phase::Ready, true)?;
        let (stream, _peer) = UnixStream::pair()?;
        let deadline = deadline(Duration::from_millis(250))?;
        let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
        if stat_change {
            rewrite_preserving_snapshot(
                &fixture.stat_path,
                b"42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98",
            )?;
        } else {
            rewrite_preserving_snapshot(
                &fixture.cmdline_path,
                b"/system/bin/app_process64\0/system/bin\0org.matrix.TEESimulator.App\0--rka-role\0xxxxx\0",
            )?;
        }
        assert_eq!(
            authorization.revalidate(&stream, &deadline),
            Err(BridgeError::PeerIdentity)
        );
    }
    Ok(())
}

#[test]
fn proc_directory_strategy_rejects_socket_hup() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_with_proc_liveness(Phase::Ready, true)?;
    let (stream, peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(250))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    drop(peer);
    assert_eq!(
        authorization.revalidate(&stream, &deadline),
        Err(BridgeError::PeerDied)
    );
    Ok(())
}

#[test]
fn close_cancels_blocked_preexposure_revalidation() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture(Phase::Preexposure)?;
    let (stream, _peer) = UnixStream::pair()?;
    let control = Control::new()?;
    let deadline = Deadline::new(Duration::from_secs(1), std::sync::Arc::clone(&control))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    control.close();
    assert_eq!(
        authorization.revalidate(&stream, &deadline),
        Err(BridgeError::PeerDied)
    );
    Ok(())
}

#[test]
fn exited_pidfd_is_a_typed_peer_death() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = std::process::Command::new("true").spawn()?;
    let pid = Pid::from_raw(i32::try_from(child.id())?).ok_or("child pid was zero")?;
    let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK)?;
    let _exit = child.wait()?;
    assert_eq!(
        deadline(Duration::from_millis(100))?.check_peer(&pidfd),
        Err(BridgeError::PeerDied)
    );
    Ok(())
}
