use std::{
    fs::{self, File},
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
    trusted_record::OpenRecord,
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str, bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rka-identity-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::write(&path, bytes)?;
        Ok(Self(path))
    }

    fn open(&self) -> Result<OwnedFd, Box<dyn std::error::Error>> {
        Ok(OwnedFd::from(File::open(&self.0)?))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
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
    files: Vec<TempFile>,
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

fn fixture(phase: Phase) -> Result<Fixture, Box<dyn std::error::Error>> {
    let executable_file = TempFile::new("executable", b"executable")?;
    let executable = executable_file.open()?;
    let executable_inode = DescriptorSnapshot::capture(&executable)?.inode();
    let expected_file = TempFile::new("expected", b"other")?;
    let expected_executable = if matches!(phase, Phase::ExecutableMismatch) {
        expected_file.open()?
    } else {
        executable_file.open()?
    };
    let record = format!(
        "version=1\ngeneration=7\nlaunch_nonce={}\nuid={}\ngid={}\npid={}\nstart_time_ticks=99\nexecutable_inode={executable_inode}\nexecutable_path={BROKER_EXECUTABLE}\nrole=DONOR\n",
        "01".repeat(32),
        0,
        0,
        std::process::id()
    );
    let record_file = TempFile::new("record", record.as_bytes())?;
    let stat_file = TempFile::new(
        "stat",
        b"42 (broker (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99",
    )?;
    let cmdline_file = TempFile::new(
        "cmdline",
        b"/system/bin/app_process64\0/system/bin\0org.matrix.TEESimulator.App\0--rka-role\0donor\0",
    )?;
    let directory_file = TempFile::new("directory", b"directory")?;
    let mut writer = None;
    let record_descriptor = if matches!(phase, Phase::Record) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        record_file.open()?
    };
    let stat = if matches!(phase, Phase::Stat) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        stat_file.open()?
    };
    let cmdline = if matches!(phase, Phase::Cmdline) {
        let (reader, held_writer) = stalled()?;
        writer = Some(held_writer);
        reader
    } else {
        cmdline_file.open()?
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
        pidfd: pidfd_open(
            Pid::from_raw(i32::try_from(std::process::id())?)
                .ok_or("current process id was zero")?,
            PidfdFlags::NONBLOCK,
        )?,
        directory: directory_file.open()?,
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
        files: vec![
            executable_file,
            expected_file,
            record_file,
            stat_file,
            cmdline_file,
            directory_file,
        ],
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
    let executable_path = fixture.files.first().ok_or("missing executable")?.0.clone();
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
    let record_path = fixture.files.get(2).ok_or("missing record")?.0.clone();
    let old_path = record_path.with_extension("held");
    let (stream, _peer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(100))?;
    let authorization = authenticate(&mut fixture.source, &stream, &deadline)?;
    fs::rename(&record_path, &old_path)?;
    fixture.files.push(TempFile(old_path));
    fs::write(&record_path, b"attacker-controlled replacement")?;
    assert_eq!(authorization.revalidate(&stream, &deadline), Ok(()));
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
