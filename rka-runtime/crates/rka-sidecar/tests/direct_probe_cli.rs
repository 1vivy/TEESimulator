//! Direct TLS probe integration coverage.

use std::{fs, process::Command};

#[test]
fn unavailable_peer_returns_bounded_redacted_typed_status() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!("rka-direct-probe-{}", std::process::id()));
    fs::create_dir_all(root.join("profiles"))?;
    let transaction = root.join("deploy-transactions/test-transaction");
    fs::create_dir_all(&transaction)?;
    let profile = root.join("profiles/direct.conf");
    fs::write(
        &profile,
        format!(
            "version=1\nrole=DONOR\nprofile_epoch=17\npeer_endpoint=192.0.2.44\npeer_spki_sha256={}\ntransport=DIRECT\n",
            "ab".repeat(32)
        ),
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("direct-probe")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_PATH", &profile)
        .env("RKA_EXPECTED_PROFILE_EPOCH", "17")
        .env("RKA_DIRECT_PROBE_ROLE", "donor")
        .env(
            "RKA_DIRECT_PROBE_RECEIPT_PATH",
            transaction.join("direct-probe.receipt"),
        )
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"direct_probe_status=unavailable\n");
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!stderr.contains("192.0.2.44"));
    assert!(!stderr.contains(&"ab".repeat(32)));
    fs::remove_dir_all(root)?;
    Ok(())
}
