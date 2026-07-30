//! Minimal command entrypoint for the standalone RKA sidecar process.

use std::{env, ffi::OsStr, io};

use rka_sidecar::{SidecarError, run};

fn main() -> Result<(), SidecarError> {
    let command = env::args_os().nth(1);
    command.as_deref().map_or_else(
        || run(OsStr::new("health"), &mut io::stdout().lock()),
        |selected| run(selected, &mut io::stdout().lock()),
    )
}
