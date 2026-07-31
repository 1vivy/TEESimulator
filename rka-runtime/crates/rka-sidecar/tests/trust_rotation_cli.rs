//! Durable trust/profile epoch CLI regression.

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn next_cli_session_reads_committed_epoch_instead_of_stale_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("rka-trust-cli-{}-{nonce}", std::process::id()));
    fs::create_dir_all(root.join("trust"))?;
    fs::write(
        root.join("trust/root-bundle.next"),
        concat!(
            "version=1\n",
            "epoch=2\n",
            "pin=cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc\n",
        ),
    )?;

    let rotate = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("rotate-roots")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_EPOCH", "1")
        .status()?;
    assert!(rotate.success());

    let next = Command::new(env!("CARGO_BIN_EXE_rka-sidecar"))
        .arg("trust-epoch")
        .env("RKA_STATE_ROOT", &root)
        .env("RKA_PROFILE_EPOCH", "1")
        .output()?;
    assert!(next.status.success());
    assert_eq!(String::from_utf8(next.stdout)?, "2\n");
    fs::remove_dir_all(root)?;
    Ok(())
}
