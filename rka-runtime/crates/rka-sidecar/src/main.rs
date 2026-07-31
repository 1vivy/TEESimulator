//! Minimal command entrypoint for the standalone RKA sidecar process.

use std::{env, error::Error, ffi::OsStr, io, thread, time::Duration};

use rka_sidecar::{provision_once, run};

fn main() -> Result<(), Box<dyn Error>> {
    let command = env::args_os().nth(1);
    if command.as_deref() == Some(OsStr::new("provision")) {
        run(OsStr::new("donor"), &mut io::stdout().lock())?;
        provision_once()?;
        return Ok(());
    }
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
