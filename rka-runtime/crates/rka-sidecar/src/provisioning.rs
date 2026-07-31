use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::digest::{SHA256, digest};
use rka_rkp::{
    AttestationStatusClient, BoundedHttpsTransport, ExpectedKey, RootBundle, RootTrustManager,
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
    let result = (|| {
        let BridgeMessage::PublicKeyResponse(_, hal_csr, hashes) = response else {
            return Err(ProvisioningRunError::Broker);
        };
        if hashes.len() != usize::from(config.key_count) {
            return Err(ProvisioningRunError::Broker);
        }
        let expected = hashes
            .iter()
            .map(|spki| {
                let value = *spki.as_array();
                ExpectedKey::new(handle(request_id, &value), value)
            })
            .collect::<Vec<_>>();
        let prepared = assemble_android_v3_body(hal_csr.as_slice(), &config.fingerprint)
            .map_err(|_| ProvisioningRunError::Validation)?;
        let signed = client
            .sign_with_request_id(prepared.body(), &fetched.challenge)
            .map_err(|_| ProvisioningRunError::Http)?;
        complete(
            &config,
            &executor,
            request_id,
            &prepared,
            signed.response().body(),
            &expected,
            &fetched.challenge,
            signed.request_id(),
        )
    })();
    if result.is_err() {
        let cancel = BridgeMessage::Cancel(RequestId::new(request_id));
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
    executor: &RoleExecutor,
    request_id: u64,
    prepared: &rka_rkp::PreparedCertificateRequest,
    response: &[u8],
    expected: &[ExpectedKey],
    challenge: &[u8],
    sign_request_id: &str,
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
    let trust = RootTrustManager::new(RootBundle::production(config.epoch));
    let session = trust
        .begin()
        .map_err(|_| ProvisioningRunError::Validation)?;
    let challenge_hash = sha256(challenge);
    let context = rka_rkp::ResponseContext::new(
        prepared.hal_csr_hash(),
        sign_request_id,
        sign_request_id,
        challenge_hash,
        challenge_hash,
        session.roots().epoch(),
        now,
    );
    let mut cancelled = false;
    let mut quarantine = |_: [u8; 32]| {
        if !cancelled {
            cancelled = true;
            let cancel = BridgeMessage::Cancel(RequestId::new(request_id));
            let _ = executor.dispatch(BrokerOperation::Donor {
                socket_path: &config.socket,
                request: &cancel,
            });
        }
    };
    let validated = validate_response(
        prepared,
        prepared.body(),
        response,
        expected,
        &context,
        session.roots(),
        &snapshot,
        &mut quarantine,
    )
    .map_err(|_| ProvisioningRunError::Validation)?;
    activate(
        &validated,
        request_id,
        session.roots().epoch(),
        &config.validator_key,
        &FileStateStore::new(&config.state_root),
        &mut quarantine,
    )?;
    Ok(())
}

fn handle(request_id: u64, spki: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&request_id.to_be_bytes());
    bytes.extend_from_slice(spki);
    sha256(&bytes)
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
