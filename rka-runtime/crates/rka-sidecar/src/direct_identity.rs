//! Root-owned transport identity initialization for direct pairing.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rcgen::{KeyPair, PublicKeyData, generate_simple_self_signed};
use ring::digest::{SHA256, digest};
use rka_transport::peer_spki_hash;
use rustls::pki_types::CertificateDer;

const HOST: &str = "teesimulator-rka.local";
const MARKER: &str = "transport-identity.commit";
const TEMP_PREFIX: &str = ".transport-identity.";
const TEMP_SUFFIX: &str = ".tmp";

struct IdentityPaths {
    key: PathBuf,
    certificate: PathBuf,
    trusted: PathBuf,
    pin: PathBuf,
    marker: PathBuf,
}

impl IdentityPaths {
    fn new(secrets: &Path, trust: &Path) -> Self {
        Self {
            key: secrets.join("transport.key"),
            certificate: trust.join("transport-self.pem"),
            trusted: trust.join("transport-trust.pem"),
            pin: trust.join("transport.pin"),
            marker: trust.join(MARKER),
        }
    }

    fn files(&self) -> [&Path; 4] {
        [
            self.key.as_path(),
            self.certificate.as_path(),
            self.trusted.as_path(),
            self.pin.as_path(),
        ]
    }
}

/// Creates the local transport identity once and returns its public SPKI pin.
pub fn initialize() -> Result<String, &'static str> {
    let state = PathBuf::from(env::var_os("RKA_STATE_ROOT").ok_or("invalid_state")?);
    let secrets = state.join("secrets");
    let trust = state.join("trust");
    require_directory(&state)?;
    require_directory(&secrets)?;
    require_directory(&trust)?;
    let final_paths = IdentityPaths::new(&secrets, &trust);
    if final_paths.marker.exists() || final_paths.marker.is_symlink() {
        return existing_receipt(&final_paths);
    }

    clean_uncommitted(&state, &final_paths)?;
    let temporary = state.join(format!("{TEMP_PREFIX}{}{TEMP_SUFFIX}", std::process::id()));
    fs::create_dir(&temporary).map_err(|_| "write_failed")?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
        .map_err(|_| "write_failed")?;
    let staged = IdentityPaths::new(&temporary, &temporary);
    let generated = generate_simple_self_signed(vec![HOST.to_owned()]).map_err(|_| "generate")?;
    let encoded_pin = hex(&peer_spki_hash(generated.cert.der()).map_err(|_| "generate")?);
    let values = [
        generated.signing_key.serialize_pem().into_bytes(),
        generated.cert.pem().into_bytes(),
        generated.cert.pem().into_bytes(),
        format!("{encoded_pin}\n").into_bytes(),
    ];
    for (index, (path, value)) in staged.files().into_iter().zip(values).enumerate() {
        write_new(path, &value)?;
        let position = index.checked_add(1).ok_or("write_failed")?;
        interrupt(&format!("stage-{position}"))?;
    }
    validate_files(&staged, &encoded_pin)?;
    write_new(
        &staged.marker,
        format!("version=1\nspki_sha256={encoded_pin}\n").as_bytes(),
    )?;
    sync_directory(&temporary)?;

    for (index, (source, destination)) in staged
        .files()
        .into_iter()
        .zip(final_paths.files())
        .enumerate()
    {
        fs::rename(source, destination).map_err(|_| "write_failed")?;
        sync_directory(destination.parent().ok_or("write_failed")?)?;
        let position = index.checked_add(1).ok_or("write_failed")?;
        interrupt(&format!("commit-{position}"))?;
    }
    fs::rename(&staged.marker, &final_paths.marker).map_err(|_| "write_failed")?;
    sync_directory(&trust)?;
    fs::remove_dir(&temporary).map_err(|_| "write_failed")?;
    sync_directory(&state)?;
    existing_receipt(&final_paths)
}

fn existing_receipt(paths: &IdentityPaths) -> Result<String, &'static str> {
    let marker = fs::symlink_metadata(&paths.marker).map_err(|_| "invalid_state")?;
    if !marker.file_type().is_file()
        || marker.permissions().mode() & 0o777 != 0o600
        || marker.len() > 128
    {
        return Err("invalid_state");
    }
    let marker = fs::read_to_string(&paths.marker).map_err(|_| "invalid_state")?;
    let encoded_pin = marker
        .strip_prefix("version=1\nspki_sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or("invalid_state")?;
    validate_files(paths, encoded_pin)?;
    Ok(format!("RESULT=IDENTITY spki_sha256={encoded_pin}\n"))
}

fn validate_files(paths: &IdentityPaths, encoded_pin: &str) -> Result<(), &'static str> {
    for path in paths.files() {
        let metadata = fs::symlink_metadata(path).map_err(|_| "invalid_state")?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 16_384
        {
            return Err("invalid_state");
        }
    }
    if encoded_pin.len() != 64
        || !encoded_pin
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("invalid_state");
    }
    let key_pem = fs::read_to_string(&paths.key).map_err(|_| "invalid_state")?;
    let certificate_pem = fs::read_to_string(&paths.certificate).map_err(|_| "invalid_state")?;
    let trusted_pem = fs::read_to_string(&paths.trusted).map_err(|_| "invalid_state")?;
    if !key_pem.starts_with("-----BEGIN PRIVATE KEY-----\n")
        || !key_pem.ends_with("-----END PRIVATE KEY-----\n")
        || !certificate_pem.starts_with("-----BEGIN CERTIFICATE-----\n")
        || !certificate_pem.ends_with("-----END CERTIFICATE-----\n")
        || certificate_pem != trusted_pem
        || fs::read_to_string(&paths.pin).map_err(|_| "invalid_state")?
            != format!("{encoded_pin}\n")
    {
        return Err("invalid_state");
    }
    let parsed_certificate = pem::parse(&certificate_pem).map_err(|_| "invalid_state")?;
    if parsed_certificate.tag() != "CERTIFICATE" {
        return Err("invalid_state");
    }
    let certificate_der = CertificateDer::from(parsed_certificate.into_contents());
    let certificate_pin = peer_spki_hash(&certificate_der).map_err(|_| "invalid_state")?;
    let key_pair = KeyPair::from_pem(&key_pem).map_err(|_| "invalid_state")?;
    let key_pin = digest(&SHA256, &key_pair.subject_public_key_info());
    if hex(&certificate_pin) != encoded_pin || hex(key_pin.as_ref()) != encoded_pin {
        return Err("invalid_state");
    }
    Ok(())
}

fn clean_uncommitted(state: &Path, paths: &IdentityPaths) -> Result<(), &'static str> {
    for path in paths.files() {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(path).map_err(|_| "invalid_state")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err("invalid_state"),
        }
    }
    for entry in fs::read_dir(state).map_err(|_| "invalid_state")? {
        let entry = entry.map_err(|_| "invalid_state")?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid_state")?;
        if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| "invalid_state")?;
            if metadata.file_type().is_dir() {
                fs::remove_dir_all(entry.path()).map_err(|_| "invalid_state")?;
            } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                fs::remove_file(entry.path()).map_err(|_| "invalid_state")?;
            } else {
                return Err("invalid_state");
            }
        }
    }
    Ok(())
}

fn interrupt(point: &str) -> Result<(), &'static str> {
    if env::var("RKA_DIRECT_IDENTITY_INTERRUPT_AFTER").as_deref() == Ok(point) {
        Err("interrupted")
    } else {
        Ok(())
    }
}

fn require_directory(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "invalid_state")?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err("invalid_state")
    }
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "write_failed")?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| "write_failed")
}

fn sync_directory(path: &Path) -> Result<(), &'static str> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "write_failed")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut encoded, byte| {
        let _ = write!(encoded, "{byte:02x}");
        encoded
    })
}
