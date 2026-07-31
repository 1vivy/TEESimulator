//! Minimal command entrypoint for the standalone RKA sidecar process.

use std::{env, ffi::OsStr, io, thread, time::Duration};

use rka_sidecar::{SidecarError, run};

fn main() -> Result<(), SidecarError> {
    let command = env::args_os().nth(1);
    let role = command.as_deref().map_or_else(
        || run(OsStr::new("health"), &mut io::stdout().lock()),
        |selected| run(selected, &mut io::stdout().lock()),
    )?;
    if role.is_some() {
        loop {
            thread::sleep(Duration::from_mins(1));
        }
    }
    Ok(())
}
