//! Minimal command entrypoint for the standalone RKA sidecar process.

use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Write as _},
    path::PathBuf,
    thread,
    time::Duration,
};

use rka_sidecar::{committed_profile_epoch, dispatch_rotation, provision_once, run};

fn main() -> Result<(), Box<dyn Error>> {
    let command = env::args_os().nth(1);
    if command.as_deref() == Some(OsStr::new("provision")) {
        run(OsStr::new("donor"), &mut io::stdout().lock())?;
        provision_once()?;
        return Ok(());
    }
    if command.as_deref() == Some(OsStr::new("rotate-roots")) {
        dispatch_rotation()?;
        return Ok(());
    }
    if command.as_deref() == Some(OsStr::new("trust-epoch")) {
        writeln!(io::stdout().lock(), "{}", committed_profile_epoch()?)?;
        return Ok(());
    }
    let role = command.as_deref().map_or_else(
        || run(OsStr::new("health"), &mut io::stdout().lock()),
        |selected| run(selected, &mut io::stdout().lock()),
    )?;
    if role.is_some() {
        loop {
            dispatch_pending_rotation()?;
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn dispatch_pending_rotation() -> Result<(), Box<dyn Error>> {
    let Some(root) = env::var_os("RKA_STATE_ROOT").map(PathBuf::from) else {
        return Ok(());
    };
    let marker = root.join("trust/rotate.request");
    if marker.is_file() {
        dispatch_rotation()?;
        fs::remove_file(marker)?;
    }
    Ok(())
}
