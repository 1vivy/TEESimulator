use crate::ValidatedResponse;
use rka_state::{
    RkpLeaseBatch, RkpLeaseError, StateStore, ValidatedChainReceipt, ValidatedReceiptRegistry,
    verify_validated_chain_receipts,
};
use thiserror::Error;

/// Failure while binding validated certificate chains to pending key leases.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ActivationError {
    /// A validated chain did not exactly match its pending lease metadata.
    #[error("validated response does not match pending leases")]
    Binding,
    /// Receipt verification or durable activation failed.
    #[error(transparent)]
    Lease(#[from] RkpLeaseError),
}

/// Activates a batch only after every validated chain and receipt matches its lease.
#[allow(
    clippy::too_many_arguments,
    reason = "activation closes independent validation, lease, receipt, store, and quarantine inputs"
)]
pub fn activate_validated_response(
    validated: &ValidatedResponse,
    pending: RkpLeaseBatch,
    receipts: &[ValidatedChainReceipt],
    registry: &ValidatedReceiptRegistry,
    store: &dyn StateStore,
    quarantine: &mut dyn FnMut([u8; 32]),
) -> Result<RkpLeaseBatch, ActivationError> {
    let matches = pending.leases().len() == validated.chains().len()
        && pending
            .leases()
            .iter()
            .zip(validated.chains())
            .all(|(lease, chain)| {
                let metadata = lease.metadata();
                usize::from(chain.order) < validated.chains().len()
                    && metadata.order == chain.order
                    && metadata.remote_handle.as_bytes() == &chain.handle
                    && metadata.spki_hash.as_bytes() == &chain.leaf_spki_hash
                    && metadata.chain.chain_hash.as_bytes() == &chain.chain_hash
                    && metadata.chain.certificate_count == chain.certificate_count
            });
    if !matches {
        validated
            .chains()
            .iter()
            .for_each(|chain| quarantine(chain.handle));
        return Err(ActivationError::Binding);
    }
    let token = verify_validated_chain_receipts(&pending, receipts, registry).map_err(|error| {
        validated
            .chains()
            .iter()
            .for_each(|chain| quarantine(chain.handle));
        ActivationError::Lease(error)
    })?;
    pending.activate(token, store).map_err(|error| {
        validated
            .chains()
            .iter()
            .for_each(|chain| quarantine(chain.handle));
        ActivationError::Lease(error)
    })
}
