//! Process-surface checks for the read-only manager appid probe.

use std::process::Command;

#[test]
fn manager_appid_command_reports_typed_status_off_android() -> Result<(), Box<dyn std::error::Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("manager-appid")
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"manager_appid_status=unsupported_platform\n"
    );
    Ok(())
}
