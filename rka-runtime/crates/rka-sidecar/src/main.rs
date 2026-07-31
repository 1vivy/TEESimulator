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

use rka_sidecar::{
    LifecycleRole, committed_profile_epoch, dispatch_rotation,
    donor::{DonorIngress, DonorRuntime},
    provision_once, run,
};

const BROKER_SOCKET: &str = "/data/adb/teesimulator-rka/run/sockets/broker.sock";

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
    if role == Some(LifecycleRole::Donor) {
        return run_donor();
    }
    if role.is_some() {
        loop {
            dispatch_pending_rotation()?;
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn run_donor() -> Result<(), Box<dyn Error>> {
    let state_root = env::var_os("RKA_STATE_ROOT")
        .map(PathBuf::from)
        .ok_or("RKA_STATE_ROOT is required")?;
    let broker_socket =
        env::var_os("RKA_DONOR_SOCKET").map_or_else(|| PathBuf::from(BROKER_SOCKET), PathBuf::from);
    let mut runtime = DonorRuntime::open(&state_root, &broker_socket);
    let ingress = DonorIngress::bind(&state_root)?;
    loop {
        ingress.serve_once(&mut runtime)?;
        dispatch_pending_rotation()?;
        thread::sleep(Duration::from_millis(25));
    }
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
