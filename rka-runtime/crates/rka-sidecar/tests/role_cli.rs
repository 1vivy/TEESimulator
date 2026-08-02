//! Production sidecar command integration tests.

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ring::digest::{SHA256, digest};

fn runtime_context(role: &str) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("rka-sidecar-role-{}-{nonce}", std::process::id()));
    fs::create_dir_all(root.join("profiles"))?;
    let profile = root.join("profiles/direct.conf");
    fs::write(
        &profile,
        format!(
            "version=1\nrole={role}\nprofile_epoch=17\npeer_endpoint=192.0.2.44\npeer_spki_sha256={}\ntransport=DIRECT\n",
            "ab".repeat(32)
        ),
    )?;
    Ok((root, profile))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

#[test]
fn donor_and_candidate_remain_live_after_ready() -> Result<(), Box<dyn std::error::Error>> {
    for role in ["donor", "candidate"] {
        let (root, profile) = runtime_context(&role.to_uppercase())?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg("--role")
            .arg(role)
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_PROFILE_PATH", &profile)
            .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
            .env(
                "RKA_PROFILE_RECEIPT_PATH",
                root.join("run/direct-profile.receipt"),
            )
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
fn direct_profile_is_consumed_before_readiness() -> Result<(), Box<dyn std::error::Error>> {
    let (root, profile) = runtime_context("DONOR")?;
    let receipt = root.join("run/direct-profile.receipt");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("--role")
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
        .env("RKA_PROFILE_RECEIPT_PATH", &receipt)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("missing role stdout"))?;
    let mut ready = String::new();
    BufReader::new(stdout).read_line(&mut ready)?;

    let receipt_text = fs::read_to_string(&receipt)?;
    let expected_profile_hash = sha256_hex(&fs::read(&profile)?);
    assert_eq!(ready, "role=donor status=READY\n");
    assert_eq!(
        receipt_text,
        format!(
            "version=1\nprofile_sha256={expected_profile_hash}\nprofile_epoch=17\npeer_pin_sha256={}\ndial_mode=CANDIDATE_DIALS\ntransport=DIRECT\n",
            sha256_hex(&[0xab_u8; 32])
        )
    );

    child.kill()?;
    child.wait()?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn partial_and_stale_direct_profiles_fail_before_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    for profile_text in [
        "version=1\nrole=DONOR\nprofile_epoch=17\n",
        "version=1\nrole=DONOR\nprofile_epoch=16\npeer_endpoint=192.0.2.44\npeer_spki_sha256=abababababababababababababababababababababababababababababababab\ntransport=DIRECT\n",
    ] {
        let (root, profile) = runtime_context("DONOR")?;
        let receipt = root.join("run/direct-profile.receipt");
        fs::write(&profile, profile_text)?;

        let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg("--role")
            .arg("donor")
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_PROFILE_PATH", &profile)
            .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
            .env("RKA_PROFILE_RECEIPT_PATH", &receipt)
            .output()?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!receipt.exists());
        fs::remove_dir_all(root)?;
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
            .arg("--role")
            .arg(role)
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_PROFILE_PATH", &profile)
            .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
            .env(
                "RKA_PROFILE_RECEIPT_PATH",
                root.join("run/direct-profile.receipt"),
            )
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
        .arg("--role")
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
        .env(
            "RKA_PROFILE_RECEIPT_PATH",
            root.join("run/direct-profile.receipt"),
        )
        .status()?;
    assert!(!oversized.success());
    fs::remove_file(&profile)?;
    fs::create_dir(&profile)?;
    let directory = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("--role")
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
        .env(
            "RKA_PROFILE_RECEIPT_PATH",
            root.join("run/direct-profile.receipt"),
        )
        .status()?;
    assert!(!directory.success());
    fs::remove_dir(&profile)?;
    let target = root.join("target.conf");
    fs::write(&target, "version=1\nrole=DONOR\nprofile_epoch=0\n")?;
    std::os::unix::fs::symlink(&target, &profile)?;
    let linked = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("--role")
        .arg("donor")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
        .env(
            "RKA_PROFILE_RECEIPT_PATH",
            root.join("run/direct-profile.receipt"),
        )
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

#[test]
fn role_argv_contract_rejects_missing_invalid_extra_and_positional_roles()
-> Result<(), Box<dyn std::error::Error>> {
    for args in [
        vec!["--role"],
        vec!["--role", "invalid"],
        vec!["--role", "donor", "extra"],
        vec!["donor"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .args(&args)
            .output()?;

        assert!(!output.status.success(), "argv={args:?}");
        assert!(output.stdout.is_empty(), "argv={args:?}");
    }
    Ok(())
}
