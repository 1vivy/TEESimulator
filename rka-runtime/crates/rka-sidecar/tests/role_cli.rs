//! Production sidecar command integration tests.

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

fn runtime_context() -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let root = std::env::temp_dir().join(format!("rka-sidecar-role-{}", std::process::id()));
    fs::create_dir_all(&root)?;
    let profile = root.join("active.conf");
    fs::write(&profile, "version=1\nrole=DONOR\nprofile_epoch=0\n")?;
    Ok((root, profile))
}

#[test]
fn donor_and_candidate_remain_live_after_ready() -> Result<(), Box<dyn std::error::Error>> {
    for role in ["donor", "candidate"] {
        let (root, profile) = runtime_context()?;
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
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready)?;
        assert_eq!(ready, format!("role={role} status=READY\n"));
        assert!(child.try_wait()?.is_none());
        child.kill()?;
        child.wait()?;
        fs::remove_dir_all(root)?;
    }
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
