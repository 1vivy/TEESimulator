use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::digest::{SHA256, digest};
use rka_rkp::{
    AttestationStatusClient, BoundedHttpsTransport, ExpectedKey, RootBundle,
    assemble_android_v3_body,
    challenge::{OsEntropy, ProvisioningHttpClient},
    returned_serials, validate_response,
};
use thiserror::Error;

use crate::{
    bridge::{BridgeMessage, BrokerOperation, PublicBytes, RequestId, RoleExecutor, SidecarRole},
    provision_activation::activate,
    provisioning_io::{FileAttemptJournal, FileBaseStore, FileStateStore, ProductionConfig},
};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Closed production provisioning-run failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningRunError {
    /// Required root-owned configuration is missing or malformed.
    #[error("provisioning configuration is unavailable")]
    Configuration,
    /// The authenticated JVM broker exchange failed.
    #[error("provisioning broker failed")]
    Broker,
    /// Fetch or signing HTTPS failed.
    #[error("provisioning HTTP failed")]
    Http,
    /// Returned status or certificate validation failed.
    #[error("provisioning validation failed")]
    Validation,
    /// Signed receipt activation or durable state failed.
    #[error("provisioning activation failed")]
    Activation,
}

/// Runs one authenticated V2 CSR-to-activated-lease production transaction.
pub fn provision_once() -> Result<(), ProvisioningRunError> {
    let config = ProductionConfig::load()?;
    let session = crate::trust_runtime::begin(config.epoch, &config.state_root)?;
    let mut client = ProvisioningHttpClient::new(
        config.base.clone(),
        (
            BoundedHttpsTransport::new().map_err(|_| ProvisioningRunError::Http)?,
            FileBaseStore::new(&config.state_root),
            OsEntropy::new(),
            FileAttemptJournal::new(&config.state_root),
        ),
    );
    let fetched = client
        .fetch(&config.info)
        .map_err(|_| ProvisioningRunError::Http)?;
    let executor = RoleExecutor::new(SidecarRole::Donor);
    let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let request = BridgeMessage::PublicKeyRequest(
        RequestId::new(request_id),
        PublicBytes::bounded(&fetched.challenge, 16, 64)
            .map_err(|_| ProvisioningRunError::Broker)?,
        config.key_count,
    );
    let response = executor
        .dispatch(BrokerOperation::Donor {
            socket_path: &config.socket,
            request: &request,
        })
        .map_err(|_| ProvisioningRunError::Broker)?;
    let mut broker_handles = Vec::new();
    let result = (|| {
        let BridgeMessage::PublicKeyResponse(_, hal_csr, keys) = response else {
            return Err(ProvisioningRunError::Broker);
        };
        if keys.len() != usize::from(config.key_count) {
            return Err(ProvisioningRunError::Broker);
        }
        broker_handles.extend(keys.iter().map(|key| *key.handle()));
        let expected = keys
            .iter()
            .enumerate()
            .map(|(order, key)| {
                if usize::from(key.order()) != order {
                    return Err(ProvisioningRunError::Broker);
                }
                Ok(ExpectedKey::with_public_hash(
                    *key.handle(),
                    *key.public_key_hash(),
                    *key.spki_hash(),
                ))
            })
            .collect::<Result<Vec<_>, ProvisioningRunError>>()?;
        let prepared = assemble_android_v3_body(hal_csr.as_slice(), &config.fingerprint)
            .map_err(|_| ProvisioningRunError::Validation)?;
        let signed = client
            .sign_with_request_id(prepared.body(), &fetched.challenge)
            .map_err(|_| ProvisioningRunError::Http)?;
        complete(
            &config,
            request_id,
            &prepared,
            signed.response().body(),
            &expected,
            &fetched.challenge,
            signed.request_id(),
            session.roots(),
        )
    })();
    if result.is_err() {
        let cancel = BridgeMessage::Cancel(
            RequestId::new(request_id),
            broker_handles
                .into_iter()
                .map(crate::bridge::Hash32::new)
                .collect(),
        );
        let _ = executor.dispatch(BrokerOperation::Donor {
            socket_path: &config.socket,
            request: &cancel,
        });
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "completion binds one exact broker/HTTP/trust transaction"
)]
fn complete(
    config: &ProductionConfig,
    request_id: u64,
    prepared: &rka_rkp::PreparedCertificateRequest,
    response: &[u8],
    expected: &[ExpectedKey],
    challenge: &[u8],
    sign_request_id: &str,
    roots: &RootBundle,
) -> Result<(), ProvisioningRunError> {
    let now = unix_seconds()?;
    let serials =
        returned_serials(response, expected.len()).map_err(|_| ProvisioningRunError::Validation)?;
    let mut status = AttestationStatusClient::new(
        BoundedHttpsTransport::new().map_err(|_| ProvisioningRunError::Http)?,
    );
    let snapshot = status
        .snapshot_for(now, serials.iter().map(String::as_str))
        .map_err(|_| ProvisioningRunError::Validation)?;
    let challenge_hash = sha256(challenge);
    let context = rka_rkp::ResponseContext::new(
        prepared.hal_csr_hash(),
        sign_request_id,
        sign_request_id,
        challenge_hash,
        challenge_hash,
        roots.epoch(),
        now,
    );
    let mut quarantine = |_: [u8; 32]| {};
    let validated = validate_response(
        prepared,
        prepared.body(),
        response,
        expected,
        &context,
        roots,
        &snapshot,
        &mut quarantine,
    )
    .map_err(|_| ProvisioningRunError::Validation)?;
    activate(
        &validated,
        request_id,
        roots.epoch(),
        &config.validator_key,
        &FileStateStore::new(&config.state_root),
        &mut quarantine,
    )?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    value
}

fn unix_seconds() -> Result<u64, ProvisioningRunError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProvisioningRunError::Configuration)
        .map(|duration| duration.as_secs())
}
