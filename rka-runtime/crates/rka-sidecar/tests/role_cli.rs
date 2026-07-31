//! Production sidecar command integration tests.

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn runtime_context(role: &str) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("rka-sidecar-role-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    let profile = root.join("active.conf");
    fs::write(
        &profile,
        format!("version=1\nrole={role}\nprofile_epoch=0\n"),
    )?;
    Ok((root, profile))
}

#[test]
fn donor_and_candidate_remain_live_after_ready() -> Result<(), Box<dyn std::error::Error>> {
    for role in ["donor", "candidate"] {
        let (root, profile) = runtime_context(&role.to_uppercase())?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg(role)
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_PROFILE_PATH", &profile)
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing role stdout"))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut ready = String::new();
            let result = BufReader::new(stdout).read_line(&mut ready).map(|_| ready);
            let _ = sender.send(result);
        });
        let ready = receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| std::io::Error::other("role readiness timeout"));
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let ready = ready??;
            assert_eq!(ready, format!("role={role} status=READY\n"));
            assert!(child.try_wait()?.is_none());
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let reader_result = reader
            .join()
            .map_err(|_| std::io::Error::other("role reader panicked"));
        let cleanup = fs::remove_dir_all(root);
        result?;
        reader_result?;
        cleanup?;
    }
    Ok(())
}

#[test]
fn cross_role_and_malformed_profiles_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for (role, profile_text) in [
        ("donor", "version=1\nrole=CANDIDATE\nprofile_epoch=0\n"),
        ("candidate", "version=1\nrole=DONOR\nprofile_epoch=0\n"),
        (
            "donor",
            "version=1\nrole=DONOR\nrole=DONOR\nprofile_epoch=0\n",
        ),
        ("donor", "version=1\nprofile_epoch=0\n"),
        ("donor", "version=1\nrole=DONOR\nprofile_epoch=bad\n"),
    ] {
        let (root, profile) = runtime_context("DONOR")?;
        fs::write(&profile, profile_text)?;
        let status = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg(role)
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_PROFILE_PATH", &profile)
            .status()?;
        assert!(!status.success());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn oversized_nonregular_and_symlink_profiles_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let (root, profile) = runtime_context("DONOR")?;
    fs::write(&profile, "x".repeat(4097))?;
    let oversized = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .status()?;
    assert!(!oversized.success());
    fs::remove_file(&profile)?;
    fs::create_dir(&profile)?;
    let directory = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .status()?;
    assert!(!directory.success());
    fs::remove_dir(&profile)?;
    let target = root.join("target.conf");
    fs::write(&target, "version=1\nrole=DONOR\nprofile_epoch=0\n")?;
    std::os::unix::fs::symlink(&target, &profile)?;
    let linked = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .status()?;
    assert!(!linked.success());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn unsupported_command_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("invalid")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("UnsupportedCommand"));
    Ok(())
}
