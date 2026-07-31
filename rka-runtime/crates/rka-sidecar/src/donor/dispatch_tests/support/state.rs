use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use rka_state::{PairedActivationRecord, RkpLeaseBatch, StateError, StateStore};

use super::{CHAIN, EPOCH, HANDLE, IRPC, PHASES, RKP_PUBLIC, SESSION};

pub(super) fn persist(
    root: &Path,
    identity_hash: [u8; 32],
    initial_transcript: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let records = FileStore(root.join("records"));
    PairedActivationRecord {
        peer_spki_hash: [0x55; 32],
        profile_id_hash: [0x66; 32],
        profile_epoch: EPOCH,
        candidate_identity_hash: identity_hash,
        session_id: SESSION,
        candidate_nonce: [0x33; 32],
        donor_nonce: [0x44; 32],
        prior_transcript_hash: initial_transcript,
    }
    .persist(&records)?;
    persist_lease(&records)?;
    RkpLeaseBatch::load_active(&records)?;
    fs::create_dir_all(root.join("lease-chains"))?;
    fs::write(root.join("lease-chains").join(hex(&HANDLE)), CHAIN)?;
    Ok(())
}

fn persist_lease(store: &FileStore) -> Result<(), StateError> {
    let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &CHAIN)
        .as_ref()
        .try_into()
        .map_err(|_| StateError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RKPL\x01");
    bytes.push(1);
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&[2; 16]);
    bytes.push(0);
    for value in [RKP_PUBLIC, [3; 32], IRPC, HANDLE, digest] {
        bytes.extend_from_slice(&value);
    }
    bytes.push(2);
    bytes.extend_from_slice(&[4; 32]);
    bytes.extend_from_slice(&EPOCH.to_be_bytes());
    for value in PHASES {
        bytes.extend_from_slice(&value);
    }
    bytes.push(2);
    store.replace(b"rkp-leases-v1", &bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
        output
    })
}

struct FileStore(PathBuf);

impl StateStore for FileStore {
    fn read(&self, key: &[u8], output: &mut [u8]) -> Result<usize, StateError> {
        let value = fs::read(self.0.join(hex(key))).map_err(|_| StateError::Missing)?;
        output
            .get_mut(..value.len())
            .ok_or(StateError::Capacity)?
            .copy_from_slice(&value);
        Ok(value.len())
    }

    fn replace(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        fs::create_dir_all(&self.0).map_err(|_| StateError::Storage)?;
        fs::write(self.0.join(hex(key)), value).map_err(|_| StateError::Storage)
    }
}
