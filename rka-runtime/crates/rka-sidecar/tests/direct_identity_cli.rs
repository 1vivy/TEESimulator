//! Direct transport identity command integration coverage.

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn identity_is_created_once_without_external_crypto_tools() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!("rka-direct-identity-{}", std::process::id()));
    fs::create_dir_all(root.join("secrets"))?;
    fs::create_dir_all(root.join("trust"))?;
    let first = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("direct-identity")
        .env("RKA_STATE_ROOT", &root)
        .env("PATH", "/nonexistent")
        .output()?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let receipt = String::from_utf8(first.stdout)?;
    let pin = receipt
        .strip_prefix("RESULT=IDENTITY spki_sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or("invalid identity receipt")?;
    assert_eq!(pin.len(), 64);
    assert!(
        pin.bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let key = root.join("secrets/transport.key");
    let certificate = root.join("trust/transport-self.pem");
    let trusted = root.join("trust/transport-trust.pem");
    let pin_path = root.join("trust/transport.pin");
    let original_key = fs::read(&key)?;
    for path in [&key, &certificate, &trusted, &pin_path] {
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(fs::read(&certificate)?, fs::read(&trusted)?);

    let second = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("direct-identity")
        .env("RKA_STATE_ROOT", &root)
        .env("PATH", "/nonexistent")
        .output()?;
    assert!(second.status.success());
    assert_eq!(receipt.as_bytes(), second.stdout);
    assert_eq!(original_key, fs::read(&key)?);
    fs::write(&pin_path, format!("{}\n", "00".repeat(32)))?;
    let tampered = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("direct-identity")
        .env("RKA_STATE_ROOT", &root)
        .env("PATH", "/nonexistent")
        .output()?;
    assert!(!tampered.status.success());
    assert_eq!(tampered.stderr, b"direct_identity_status=invalid_state\n");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn every_staging_and_commit_interruption_retries_as_one_generation()
-> Result<(), Box<dyn std::error::Error>> {
    for point in (1..=4)
        .map(|value| format!("stage-{value}"))
        .chain((1..=4).map(|value| format!("commit-{value}")))
    {
        let root = std::env::temp_dir().join(format!(
            "rka-direct-identity-interrupt-{}-{point}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("secrets"))?;
        fs::create_dir_all(root.join("trust"))?;
        let interrupted = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg("direct-identity")
            .env("RKA_STATE_ROOT", &root)
            .env("RKA_DIRECT_IDENTITY_INTERRUPT_AFTER", &point)
            .output()?;
        assert!(!interrupted.status.success(), "{point}");
        let retried = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
            .arg("direct-identity")
            .env("RKA_STATE_ROOT", &root)
            .output()?;
        assert!(retried.status.success(), "{point}");
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn uncommitted_partial_final_set_is_cleaned_before_retry() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!(
        "rka-direct-identity-partial-{}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("secrets"))?;
    fs::create_dir_all(root.join("trust"))?;
    fs::write(root.join("secrets/transport.key"), b"partial")?;
    let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("direct-identity")
        .env("RKA_STATE_ROOT", &root)
        .output()?;
    assert!(output.status.success());
    assert_ne!(fs::read(root.join("secrets/transport.key"))?, b"partial");
    fs::remove_dir_all(root)?;
    Ok(())
}
