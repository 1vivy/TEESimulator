use std::path::Path;

use rka_state::CertifiedLeaseMetadata;

use super::DonorError;
use crate::provisioning_io::load_lease_chain;

pub(super) fn load_verified_chain(
    root: &Path,
    lease: &CertifiedLeaseMetadata,
) -> Result<Vec<Vec<u8>>, DonorError> {
    let chain =
        load_lease_chain(root, lease.remote_handle.as_bytes()).map_err(|_| DonorError::Storage)?;
    let encoded = chain.concat();
    let hash: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &encoded)
        .as_ref()
        .try_into()
        .map_err(|_| DonorError::Storage)?;
    if chain.len() != usize::from(lease.chain.certificate_count)
        || hash != *lease.chain.chain_hash.as_bytes()
    {
        return Err(DonorError::Storage);
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rka_state::{
        BatchId, ChainHash, IrpcIdentityHash, LeaseId, PublicChainMetadata, PublicKeyHash,
        RemoteKeyHandle, SpkiHash, ValidatorPublicKey,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn loaded_chain_must_match_the_active_lease_hash_and_count() {
        // Given
        let root = root();
        let chain = [0x30, 1, 0, 0x30, 1, 1];
        let handle = [9; 32];
        let directory = root.join("lease-chains");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(hex(&handle)), chain).unwrap();
        let mut lease = lease(handle, chain);

        // When / Then
        assert_eq!(
            load_verified_chain(&root, &lease),
            Ok(vec![vec![0x30, 1, 0], vec![0x30, 1, 1]])
        );
        lease.chain.certificate_count = 1;
        assert_eq!(load_verified_chain(&root, &lease), Err(DonorError::Storage));
        lease.chain.certificate_count = 2;
        lease.chain.chain_hash = ChainHash::new([0; 32]);
        assert_eq!(load_verified_chain(&root, &lease), Err(DonorError::Storage));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn lease(handle: [u8; 32], chain: [u8; 6]) -> CertifiedLeaseMetadata {
        let hash = ring::digest::digest(&ring::digest::SHA256, &chain);
        CertifiedLeaseMetadata {
            lease_id: LeaseId::new([1; 16]),
            batch_id: BatchId::new([2; 16]),
            order: 0,
            public_key_hash: PublicKeyHash::new([3; 32]),
            spki_hash: SpkiHash::new([4; 32]),
            irpc_identity_hash: IrpcIdentityHash::new([5; 32]),
            remote_handle: RemoteKeyHandle::new(handle),
            chain: PublicChainMetadata {
                chain_hash: ChainHash::new(hash.as_ref().try_into().unwrap()),
                certificate_count: 2,
            },
            validator_public_key: ValidatorPublicKey::new([6; 32]),
            profile_epoch: 7,
            phase_hashes: [[8; 32]; 5],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
            output
        })
    }

    fn root() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rka-donor-chain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
