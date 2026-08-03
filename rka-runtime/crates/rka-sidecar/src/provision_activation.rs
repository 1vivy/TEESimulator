use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rka_rkp::ValidatedResponse;
use rka_state::{
    BatchId, CertifiedLeaseMetadata, ChainHash, IrpcIdentityHash, LeaseId, PublicChainMetadata,
    PublicKeyHash, RemoteKeyHandle, RkpLease, RkpLeaseBatch, SpkiHash, StateStore,
    ValidatedCertificationToken, ValidatedChainClaims, ValidatedChainReceipt,
    ValidatedReceiptRegistry, ValidatorPublicKey, verify_validated_chain_receipts,
};
use rustix::process::{getegid, geteuid};

use crate::{ProvisioningRunError, provisioning::ProvisioningActivationStage};

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling provisioning coordinator initializes the private validator"
)]
pub(super) fn ensure_validator_key(path: &Path) -> Result<(), ProvisioningRunError> {
    let parent = path.parent().ok_or(ProvisioningRunError::Configuration)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| ProvisioningRunError::Configuration)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.mode() & 0o777 != 0o700
        || parent_metadata.uid() != geteuid().as_raw()
        || parent_metadata.gid() != getegid().as_raw()
    {
        return Err(ProvisioningRunError::Configuration);
    }
    match validate_validator_key(path) {
        Ok(()) => return Ok(()),
        Err(ProvisioningRunError::Configuration)
            if matches!(
                fs::symlink_metadata(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error),
    }
    let temporary = parent.join(".validator.pk8.tmp");
    if let Ok(metadata) = fs::symlink_metadata(&temporary) {
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != geteuid().as_raw()
            || metadata.gid() != getegid().as_raw()
        {
            return Err(ProvisioningRunError::Configuration);
        }
        fs::remove_file(&temporary).map_err(|_| ProvisioningRunError::Configuration)?;
    }
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| ProvisioningRunError::Configuration)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(document.as_ref())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(ProvisioningRunError::Configuration);
    }
    validate_validator_key(path)
}

fn validate_validator_key(path: &Path) -> Result<(), ProvisioningRunError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProvisioningRunError::Configuration)?;
    if !metadata.file_type().is_file()
        || metadata.len() > 4096
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != geteuid().as_raw()
        || metadata.gid() != getegid().as_raw()
    {
        return Err(ProvisioningRunError::Configuration);
    }
    let document = fs::read(path).map_err(|_| ProvisioningRunError::Configuration)?;
    Ed25519KeyPair::from_pkcs8(&document)
        .map(|_| ())
        .map_err(|_| ProvisioningRunError::Configuration)
}

#[allow(
    clippy::redundant_pub_crate,
    clippy::too_many_arguments,
    reason = "sibling coordinator binds validated data, trust, storage, and quarantine"
)]
pub(crate) struct PreparedActivation {
    pending: RkpLeaseBatch,
    token: ValidatedCertificationToken,
}

impl PreparedActivation {
    pub(crate) const fn binding_hash(&self) -> &[u8; 32] {
        self.token.binding_hash()
    }

    pub(crate) fn activate(
        self,
        store: &dyn StateStore,
    ) -> Result<RkpLeaseBatch, ProvisioningRunError> {
        self.pending.activate(self.token, store).map_err(|_| {
            ProvisioningRunError::ActivationStage(ProvisioningActivationStage::LeaseCommit)
        })
    }
}

#[allow(
    clippy::redundant_pub_crate,
    clippy::too_many_arguments,
    reason = "sibling coordinator binds validated data, broker batch, trust, and quarantine"
)]
pub(crate) fn prepare(
    validated: &ValidatedResponse,
    request_id: u64,
    broker_batch_id: [u8; 16],
    irpc_identity_hash: [u8; 32],
    phase_hashes: [[u8; 32]; 5],
    epoch: u64,
    validator_path: &Path,
    quarantine: &mut dyn FnMut([u8; 32]),
) -> Result<PreparedActivation, ProvisioningRunError> {
    let document = fs::read(validator_path).map_err(|_| ProvisioningRunError::Configuration)?;
    if document.len() > 4096 {
        return Err(ProvisioningRunError::Configuration);
    }
    let signer =
        Ed25519KeyPair::from_pkcs8(&document).map_err(|_| ProvisioningRunError::Configuration)?;
    let validator = ValidatorPublicKey::new(
        signer
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| ProvisioningRunError::Configuration)?,
    );
    let batch_id = BatchId::new(broker_batch_id);
    let identity = IrpcIdentityHash::new(irpc_identity_hash);
    let mut leases = Vec::with_capacity(validated.chains().len());
    let mut claims = Vec::with_capacity(validated.chains().len());
    for chain in validated.chains() {
        let public = PublicKeyHash::new(chain.public_key_hash);
        let spki = SpkiHash::new(chain.leaf_spki_hash);
        let lease_id = LeaseId::new(first::<16>(&binding(
            b"lease",
            request_id,
            &chain.leaf_spki_hash,
        )));
        let metadata = CertifiedLeaseMetadata {
            lease_id,
            batch_id,
            order: chain.order,
            public_key_hash: public,
            spki_hash: spki,
            irpc_identity_hash: identity,
            remote_handle: RemoteKeyHandle::new(chain.handle),
            chain: PublicChainMetadata {
                chain_hash: ChainHash::new(chain.chain_hash),
                certificate_count: chain.certificate_count,
            },
            validator_public_key: validator,
            profile_epoch: epoch,
            phase_hashes,
        };
        leases.push(RkpLease::certified(metadata).map_err(|_| {
            ProvisioningRunError::ActivationStage(ProvisioningActivationStage::LeasePreparation)
        })?);
        claims.push(ValidatedChainClaims {
            lease_id,
            batch_id,
            order: chain.order,
            public_key_hash: public,
            leaf_spki_hash: spki,
            chain_hash: metadata.chain.chain_hash,
            certificate_count: chain.certificate_count,
            profile_epoch: epoch,
        });
    }
    let pending = RkpLeaseBatch::new(leases).map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::LeasePreparation)
    })?;
    let receipts = claims
        .into_iter()
        .map(|value| {
            let signature = signer.sign(&value.canonical_bytes());
            let bytes = signature.as_ref().try_into().map_err(|_| {
                ProvisioningRunError::ActivationStage(ProvisioningActivationStage::LeasePreparation)
            })?;
            Ok(ValidatedChainReceipt::new(value, bytes))
        })
        .collect::<Result<Vec<_>, ProvisioningRunError>>()?;
    let registry = ValidatedReceiptRegistry::open().map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::ReceiptRegistry)
    })?;
    let token = verify_validated_chain_receipts(&pending, &receipts, &registry).map_err(|_| {
        for chain in validated.chains() {
            quarantine(chain.handle);
        }
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::ReceiptVerification)
    })?;
    Ok(PreparedActivation { pending, token })
}

fn binding(domain: &[u8], request_id: u64, key: &[u8; 32]) -> [u8; 32] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(b"TEESimulator-RS activation v1\0");
    context.update(domain);
    context.update(&request_id.to_be_bytes());
    context.update(key);
    let mut value = [0; 32];
    value.copy_from_slice(context.finish().as_ref());
    value
}

fn first<const N: usize>(value: &[u8; 32]) -> [u8; N] {
    let mut output = [0; N];
    if let Some(prefix) = value.get(..N) {
        output.copy_from_slice(prefix);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::ensure_validator_key;

    #[test]
    fn validator_key_is_generated_once_with_private_mode() {
        let root = unique_root();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("validator.pk8");

        ensure_validator_key(&path).unwrap();
        let first = fs::read(&path).unwrap();
        ensure_validator_key(&path).unwrap();

        assert_eq!(fs::read(&path).unwrap(), first);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validator_key_rejects_a_symlink_target() {
        let root = unique_root();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.join("target");
        fs::write(&target, b"not a key").unwrap();
        symlink(&target, root.join("validator.pk8")).unwrap();

        assert!(ensure_validator_key(&root.join("validator.pk8")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn unique_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rka-validator-{}-{nonce}", process::id()))
    }
}
