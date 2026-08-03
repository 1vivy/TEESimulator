//! Minimal command entrypoint for the standalone RKA sidecar process.

use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rka_sidecar::{
    LifecycleRole, committed_profile_epoch, dispatch_rotation, donor::DonorIngress, provision_once,
    run,
};

const BROKER_SOCKET: &str = "/data/adb/teesimulator-rka/run/sockets/broker.sock";

fn main() -> ExitCode {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        let _ = writeln!(
            io::stderr().lock(),
            "crypto_provider_status=configuration_error"
        );
        return ExitCode::FAILURE;
    }
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let command = args.first().map(OsString::as_os_str);
    if command == Some(OsStr::new("manager-appid")) {
        return match rka_ksu_manager::probe_manager_appid() {
            Ok(appid) => {
                if writeln!(io::stdout().lock(), "{appid}").is_ok() {
                    ExitCode::SUCCESS
                } else {
                    let _ = writeln!(io::stderr().lock(), "manager_appid_status=output_error");
                    ExitCode::from(2)
                }
            }
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "manager_appid_status={}",
                    error.status()
                );
                ExitCode::from(2)
            }
        };
    }
    if command == Some(OsStr::new("direct-probe")) {
        return match rka_sidecar::direct_profile::probe() {
            Ok(receipt) => {
                if write!(io::stdout().lock(), "{receipt}").is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(status) => {
                let _ = writeln!(io::stderr().lock(), "direct_probe_status={status}");
                ExitCode::from(2)
            }
        };
    }
    if command == Some(OsStr::new("direct-identity")) {
        return match rka_sidecar::direct_identity::initialize() {
            Ok(receipt) => {
                if write!(io::stdout().lock(), "{receipt}").is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(status) => {
                let _ = writeln!(io::stderr().lock(), "direct_identity_status={status}");
                ExitCode::from(2)
            }
        };
    }
    if command == Some(OsStr::new("activate-direct")) {
        return activate_direct(&args);
    }
    if command == Some(OsStr::new("status-probe")) {
        return status_probe();
    }
    if command == Some(OsStr::new("synthetic-lease-probe")) {
        return synthetic_lease_probe();
    }
    if command == Some(OsStr::new("synthetic-lease-issue")) {
        return synthetic_lease_issue();
    }
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            report_error(&*error);
            return ExitCode::FAILURE;
        }
    };
    match execute(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&*error);
            ExitCode::FAILURE
        }
    }
}

fn synthetic_lease_issue() -> ExitCode {
    match rka_sidecar::synthetic_lease_issue::issue() {
        Ok(receipt) => {
            if writeln!(io::stdout().lock(), "{receipt}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(status) => {
            let _ = writeln!(io::stderr().lock(), "synthetic_lease_issue_status={status}");
            ExitCode::from(2)
        }
    }
}

fn synthetic_lease_probe() -> ExitCode {
    match rka_sidecar::synthetic_lease_probe::probe() {
        Ok(receipt) => {
            if writeln!(io::stdout().lock(), "{receipt}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(status) => {
            let _ = writeln!(io::stderr().lock(), "synthetic_lease_probe_status={status}");
            ExitCode::from(2)
        }
    }
}

fn status_probe() -> ExitCode {
    let result = (|| -> Result<(), Box<dyn Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut client =
            rka_rkp::AttestationStatusClient::new(rka_rkp::BoundedHttpsTransport::new()?);
        client.snapshot_for_diagnostic(now, std::iter::empty())?;
        writeln!(io::stdout().lock(), "status_probe=READY")?;
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&*error);
            ExitCode::FAILURE
        }
    }
}

fn activate_direct(args: &[OsString]) -> ExitCode {
    let Some(role_arg) = args.get(1).filter(|_| args.len() == 2) else {
        let _ = writeln!(
            io::stderr().lock(),
            "direct_activation_status=invalid_context"
        );
        return ExitCode::from(2);
    };
    let Ok(role) = LifecycleRole::parse(role_arg.as_os_str()) else {
        let _ = writeln!(
            io::stderr().lock(),
            "direct_activation_status=invalid_context"
        );
        return ExitCode::from(2);
    };
    match rka_sidecar::direct_activation::activate(role) {
        Ok(receipt) => {
            if write!(io::stdout().lock(), "{receipt}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(status) => {
            let _ = writeln!(io::stderr().lock(), "direct_activation_status={status}");
            ExitCode::from(2)
        }
    }
}

fn parse_command(args: &[std::ffi::OsString]) -> Result<Option<&OsStr>, Box<dyn Error>> {
    let Some(command) = args.first().map(OsString::as_os_str) else {
        return Ok(None);
    };
    if command == OsStr::new("--role") {
        if args.len() != 2 {
            return Err("--role requires exactly one role value".into());
        }
        let Some(role) = args.get(1).map(OsString::as_os_str) else {
            return Err("--role requires exactly one role value".into());
        };
        if role != OsStr::new("donor") && role != OsStr::new("candidate") {
            return Err("--role accepts only donor or candidate".into());
        }
        return Ok(Some(role));
    }
    if command == OsStr::new("donor") || command == OsStr::new("candidate") {
        return Err("positional roles are not supported; use --role".into());
    }
    Ok(Some(command))
}

fn execute(command: Option<&OsStr>) -> Result<(), Box<dyn Error>> {
    if command == Some(OsStr::new("provision")) {
        run(OsStr::new("donor"), &mut io::stdout().lock())?;
        provision_once()?;
        writeln!(io::stdout().lock(), "RESULT=PROVISIONED")?;
        return Ok(());
    }
    if command == Some(OsStr::new("rotate-roots")) {
        dispatch_rotation()?;
        return Ok(());
    }
    if command == Some(OsStr::new("trust-epoch")) {
        writeln!(io::stdout().lock(), "{}", committed_profile_epoch()?)?;
        return Ok(());
    }
    let role = command.map_or_else(
        || run(OsStr::new("health"), &mut io::stdout().lock()),
        |selected| run(selected, &mut io::stdout().lock()),
    )?;
    match role {
        Some(LifecycleRole::Donor) => return run_donor(),
        Some(LifecycleRole::Candidate)
            if rka_sidecar::direct_profile::donor_dials(LifecycleRole::Candidate)? =>
        {
            return rka_sidecar::direct_session::run_candidate().map_err(Into::into);
        }
        Some(LifecycleRole::Candidate) => loop {
            dispatch_pending_rotation()?;
            thread::sleep(Duration::from_secs(1));
        },
        Some(_) => return Err("unsupported runtime role".into()),
        None => {}
    }
    Ok(())
}

#[expect(
    clippy::use_debug,
    reason = "preserves the established sidecar CLI error surface"
)]
fn report_error(error: &dyn Error) {
    let _ = writeln!(io::stderr().lock(), "Error: {error:?}");
}

fn run_donor() -> Result<(), Box<dyn Error>> {
    if rka_sidecar::direct_profile::donor_dials(LifecycleRole::Donor)? {
        return rka_sidecar::direct_session::run_donor_bridge().map_err(Into::into);
    }
    let state_root = env::var_os("RKA_STATE_ROOT")
        .map(PathBuf::from)
        .ok_or("RKA_STATE_ROOT is required")?;
    let broker_socket =
        env::var_os("RKA_DONOR_SOCKET").map_or_else(|| PathBuf::from(BROKER_SOCKET), PathBuf::from);
    let mut runtime = rka_sidecar::donor::DonorRuntime::open(&state_root, &broker_socket);
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
