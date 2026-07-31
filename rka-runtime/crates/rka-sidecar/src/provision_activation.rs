use std::{fs, path::Path};

use ring::signature::{Ed25519KeyPair, KeyPair};
use rka_rkp::{ValidatedResponse, activate_validated_response};
use rka_state::{
    BatchId, CertifiedLeaseMetadata, ChainHash, IrpcIdentityHash, LeaseId, PublicChainMetadata,
    PublicKeyHash, RemoteKeyHandle, RkpLease, RkpLeaseBatch, SpkiHash, StateStore,
    ValidatedChainClaims, ValidatedChainReceipt, ValidatedReceiptRegistry, ValidatorPublicKey,
};

use crate::ProvisioningRunError;

#[allow(
    clippy::redundant_pub_crate,
    clippy::too_many_arguments,
    reason = "sibling coordinator binds validated data, trust, storage, and quarantine"
)]
pub(crate) fn activate(
    validated: &ValidatedResponse,
    request_id: u64,
    epoch: u64,
    validator_path: &Path,
    store: &dyn StateStore,
    quarantine: &mut dyn FnMut([u8; 32]),
) -> Result<RkpLeaseBatch, ProvisioningRunError> {
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
    let batch_id = BatchId::new(first::<16>(&binding(b"batch", request_id, &[0; 32])));
    let identity = IrpcIdentityHash::new(binding(b"irpc", request_id, &[0; 32]));
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
        };
        leases.push(RkpLease::certified(metadata).map_err(|_| ProvisioningRunError::Activation)?);
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
    let pending = RkpLeaseBatch::new(leases).map_err(|_| ProvisioningRunError::Activation)?;
    let receipts = claims
        .into_iter()
        .map(|value| {
            let signature = signer.sign(&value.canonical_bytes());
            let bytes = signature
                .as_ref()
                .try_into()
                .map_err(|_| ProvisioningRunError::Activation)?;
            Ok(ValidatedChainReceipt::new(value, bytes))
        })
        .collect::<Result<Vec<_>, ProvisioningRunError>>()?;
    let registry =
        ValidatedReceiptRegistry::open().map_err(|_| ProvisioningRunError::Activation)?;
    activate_validated_response(validated, pending, &receipts, &registry, store, quarantine)
        .map_err(|_| ProvisioningRunError::Activation)
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
