use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::digest::{SHA256, digest};
use rka_rkp::{
    AttestationStatusClient, BoundedHttpsTransport, ClientError, ExpectedKey, RootBundle,
    assemble_android_v3_body,
    challenge::{OsEntropy, ProvisioningHttpClient},
    outcome::{
        AttemptDigests, AttemptIdentity, AttemptIds, DurablePostingJournal, DurableResponseJournal,
        OutcomeError, validate_fresh_attempt,
    },
    returned_serials, validate_response,
};
use rka_state::{
    AmbiguousMaterial, CleanupIntent, CrashRecovery, MutationCrashState, QuarantineActions,
    QuarantineLedger,
};
use thiserror::Error;

use crate::{
    bridge::{
        BridgeMessage, BrokerBatchId, BrokerCertificationMetadata, BrokerOperation, Hash32,
        PublicBytes, RequestId, RoleExecutor, SidecarRole,
    },
    provision_activation::{ensure_validator_key, prepare},
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
    /// Fetch or signing HTTPS failed with a redacted client category.
    #[error("provisioning HTTP failed: {0}")]
    Http(ClientError),
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
    ensure_validator_key(&config.validator_key)?;
    let session = crate::trust_runtime::begin(config.epoch, &config.state_root)?;
    let mut client = ProvisioningHttpClient::new(
        config.base.clone(),
        (
            BoundedHttpsTransport::new().map_err(ProvisioningRunError::Http)?,
            FileBaseStore::new(&config.state_root),
            OsEntropy::new(),
            FileAttemptJournal::new(&config.state_root),
        ),
    );
    let fetched = client
        .fetch(&config.info)
        .map_err(ProvisioningRunError::Http)?;
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
    let mut broker_batch_id = None;
    let result = (|| {
        let BridgeMessage::PublicKeyResponse(_, hal_csr, batch_id, irpc_identity_hash, keys) =
            response
        else {
            return Err(ProvisioningRunError::Broker);
        };
        if keys.len() != usize::from(config.key_count) {
            return Err(ProvisioningRunError::Broker);
        }
        broker_batch_id = Some(*batch_id.as_array());
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
        let identity = attempt_identity(
            (request_id, *batch_id.as_array()),
            (&fetched.challenge, &prepared.hal_csr_hash()),
            &broker_handles,
        )?;
        let (sign_request_id, signed_body) =
            post_with_recovery((&config, &executor), &identity, || {
                client.sign_with_request_id(prepared.body(), &fetched.challenge)
            })?;
        complete(
            &config,
            &executor,
            request_id,
            *batch_id.as_array(),
            *irpc_identity_hash.as_array(),
            &prepared,
            &signed_body,
            &expected,
            &fetched.challenge,
            &sign_request_id,
            session.roots(),
        )
    })();
    if result.is_err()
        && !matches!(result, Err(ProvisioningRunError::Http(_)))
        && !broker_handles.is_empty()
    {
        let batch_id = broker_batch_id.ok_or(ProvisioningRunError::Activation)?;
        cancel_generated_batch(
            &executor,
            (&config.socket, request_id),
            (batch_id, &broker_handles),
        )?;
    }
    result
}

fn cancel_generated_batch(
    executor: &RoleExecutor,
    request: (&std::path::Path, u64),
    material: ([u8; 16], &[[u8; 32]]),
) -> Result<(), ProvisioningRunError> {
    let (socket, request_id) = request;
    let (batch_id, handles) = material;
    let mut request = [0_u8; 16];
    request[8..].copy_from_slice(&request_id.to_be_bytes());
    let material = AmbiguousMaterial::new(request, batch_id, handles.to_vec())
        .map_err(|_| ProvisioningRunError::Activation)?;
    let action_ids = material
        .cleanup_intents()
        .iter()
        .map(|action| Hash32::new(*action.action_id()))
        .collect();
    let cancel = BridgeMessage::Cancel(
        RequestId::new(request_id),
        handles.iter().copied().map(Hash32::new).collect(),
        Some((BrokerBatchId::new(batch_id), action_ids)),
    );
    let response = executor
        .dispatch(BrokerOperation::Donor {
            socket_path: socket,
            request: &cancel,
        })
        .map_err(|_| ProvisioningRunError::Broker)?;
    match response {
        BridgeMessage::Cancel(id, handles, None)
            if id == RequestId::new(request_id) && handles.is_empty() =>
        {
            Ok(())
        }
        _ => Err(ProvisioningRunError::Broker),
    }
}

fn attempt_identity(
    ids: (u64, [u8; 16]),
    digests: (&[u8], &[u8; 32]),
    handles: &[[u8; 32]],
) -> Result<AttemptIdentity, ProvisioningRunError> {
    let (request_id, batch_id) = ids;
    let (challenge, csr_hash) = digests;
    let mut request = [0_u8; 16];
    request[8..].copy_from_slice(&request_id.to_be_bytes());
    AttemptIdentity::new(
        AttemptIds::new(request, batch_id),
        AttemptDigests::new(sha256(challenge), *csr_hash),
        handles.to_vec(),
    )
    .map_err(|_| ProvisioningRunError::Activation)
}

fn post_with_recovery<F>(
    boundaries: (&ProductionConfig, &RoleExecutor),
    identity: &AttemptIdentity,
    mut post: F,
) -> Result<(String, Vec<u8>), ProvisioningRunError>
where
    F: FnMut() -> Result<rka_rkp::SignedCertificateResponse, ClientError>,
{
    let (config, executor) = boundaries;
    let store = FileStateStore::new(&config.state_root);
    let responses = DurableResponseJournal::new(&store);
    match responses.replay_for(identity) {
        Ok(Some(replayed)) => return decode_durable_response(&replayed),
        Ok(None) | Err(OutcomeError::StaleReplay) => {}
        Err(_) => return Err(ProvisioningRunError::Activation),
    }
    let posting = DurablePostingJournal::new(&store);
    if let Some(previous) = posting
        .load()
        .map_err(|_| ProvisioningRunError::Activation)?
    {
        if previous == *identity {
            quarantine(config, executor, &previous)?;
            return Err(ProvisioningRunError::Http(ClientError::PostAmbiguous));
        }
        validate_fresh_attempt(&previous, identity)
            .map_err(|_| ProvisioningRunError::Activation)?;
        match responses.replay_for(&previous) {
            Ok(Some(_)) => {}
            Ok(None) | Err(OutcomeError::StaleReplay) => quarantine(config, executor, &previous)?,
            Err(_) => return Err(ProvisioningRunError::Activation),
        }
    }
    posting
        .record(identity)
        .map_err(|_| ProvisioningRunError::Activation)?;
    match post() {
        Ok(signed) => {
            let durable = encode_durable_response(signed.request_id(), signed.response().body())?;
            responses
                .record_validated(identity, &durable)
                .map_err(|_| ProvisioningRunError::Activation)?;
            Ok((
                signed.request_id().to_owned(),
                signed.response().body().to_vec(),
            ))
        }
        Err(error) => {
            quarantine(config, executor, identity)?;
            Err(ProvisioningRunError::Http(error))
        }
    }
}

fn encode_durable_response(
    request_id: &str,
    response: &[u8],
) -> Result<Vec<u8>, ProvisioningRunError> {
    if request_id.len() != 36 || request_id.as_bytes().contains(&b'\n') {
        return Err(ProvisioningRunError::Validation);
    }
    let mut durable = Vec::with_capacity(37_usize.saturating_add(response.len()));
    durable.extend_from_slice(request_id.as_bytes());
    durable.push(b'\n');
    durable.extend_from_slice(response);
    Ok(durable)
}

fn decode_durable_response(durable: &[u8]) -> Result<(String, Vec<u8>), ProvisioningRunError> {
    let request = durable.get(..36).ok_or(ProvisioningRunError::Validation)?;
    if durable.get(36) != Some(&b'\n') {
        return Err(ProvisioningRunError::Validation);
    }
    let request = std::str::from_utf8(request).map_err(|_| ProvisioningRunError::Validation)?;
    let response = durable
        .get(37..)
        .ok_or(ProvisioningRunError::Validation)?
        .to_vec();
    Ok((request.to_owned(), response))
}

fn quarantine(
    config: &ProductionConfig,
    executor: &RoleExecutor,
    identity: &AttemptIdentity,
) -> Result<(), ProvisioningRunError> {
    let material = AmbiguousMaterial::new(
        *identity.request_id(),
        *identity.batch_id(),
        identity.handles().to_vec(),
    )
    .map_err(|_| ProvisioningRunError::Activation)?;
    let store = FileStateStore::new(&config.state_root);
    let mut ledger = QuarantineLedger::new(&store);
    let mut actions = BrokerQuarantineActions {
        executor,
        socket: &config.socket,
        material: &material,
        acknowledged: false,
    };
    ledger
        .recover_crash(
            CrashRecovery::new(MutationCrashState::PostAmbiguous, &material),
            &mut actions,
        )
        .map_err(|_| ProvisioningRunError::Activation)
}

struct BrokerQuarantineActions<'a> {
    executor: &'a RoleExecutor,
    socket: &'a std::path::Path,
    material: &'a AmbiguousMaterial,
    acknowledged: bool,
}

impl QuarantineActions for BrokerQuarantineActions<'_> {
    fn execute(&mut self, intent: CleanupIntent) -> bool {
        if self.acknowledged {
            return self
                .material
                .cleanup_intents()
                .iter()
                .any(|expected| expected == &intent);
        }
        if !self
            .material
            .cleanup_intents()
            .iter()
            .any(|expected| expected == &intent)
        {
            return false;
        }
        let mut request_bytes = [0_u8; 8];
        request_bytes.copy_from_slice(&self.material.request_id()[8..]);
        let action_ids = self
            .material
            .cleanup_intents()
            .iter()
            .map(|action| Hash32::new(*action.action_id()))
            .collect();
        let request = BridgeMessage::Cancel(
            RequestId::new(u64::from_be_bytes(request_bytes)),
            self.material
                .handles()
                .iter()
                .copied()
                .map(Hash32::new)
                .collect(),
            Some((
                crate::bridge::BrokerBatchId::new(*self.material.batch_id()),
                action_ids,
            )),
        );
        self.acknowledged = self
            .executor
            .dispatch(BrokerOperation::Donor {
                socket_path: self.socket,
                request: &request,
            })
            .is_ok();
        self.acknowledged
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "completion binds one exact broker/HTTP/trust transaction"
)]
fn complete(
    config: &ProductionConfig,
    executor: &RoleExecutor,
    request_id: u64,
    broker_batch_id: [u8; 16],
    irpc_identity_hash: [u8; 32],
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
        BoundedHttpsTransport::new().map_err(ProvisioningRunError::Http)?,
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
    let encoded_chains = rka_rkp::parse_signed_certificates(response, expected.len())
        .map_err(|_| ProvisioningRunError::Validation)?;
    let phase_hashes = [
        prepared.hal_csr_hash(),
        sha256(prepared.body()),
        challenge_hash,
        sha256(response),
        chain_set_hash(&encoded_chains)?,
    ];
    let prepared_activation = prepare(
        &validated,
        request_id,
        broker_batch_id,
        irpc_identity_hash,
        phase_hashes,
        roots.epoch(),
        &config.validator_key,
        &mut quarantine,
    )?;
    let certification = BridgeMessage::CertificationRequest(
        RequestId::new(request_id),
        crate::bridge::BrokerBatchId::new(broker_batch_id),
        validated
            .chains()
            .iter()
            .map(|chain| {
                BrokerCertificationMetadata::new(
                    chain.order,
                    chain.handle,
                    chain.public_key_hash,
                    chain.leaf_spki_hash,
                    chain.chain_hash,
                    chain.certificate_count,
                )
                .map_err(|_| ProvisioningRunError::Broker)
            })
            .collect::<Result<Vec<_>, ProvisioningRunError>>()?,
        roots.epoch(),
        Hash32::new(*prepared_activation.binding_hash()),
    );
    let acknowledgement = executor
        .dispatch(BrokerOperation::Donor {
            socket_path: &config.socket,
            request: &certification,
        })
        .map_err(|_| ProvisioningRunError::Broker)?;
    let BridgeMessage::CertificationAck(_, acknowledged_batch, acknowledged_binding) =
        acknowledgement
    else {
        return Err(ProvisioningRunError::Broker);
    };
    if acknowledged_batch.as_array() != &broker_batch_id
        || acknowledged_binding.as_array() != prepared_activation.binding_hash()
    {
        return Err(ProvisioningRunError::Broker);
    }
    let handles = validated
        .chains()
        .iter()
        .map(|chain| chain.handle)
        .collect::<Vec<_>>();
    crate::provisioning_io::persist_lease_chains(&config.state_root, &handles, &encoded_chains)
        .map_err(|_| ProvisioningRunError::Activation)?;
    prepared_activation.activate(&FileStateStore::new(&config.state_root))?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    value
}

fn chain_set_hash(chains: &[Vec<u8>]) -> Result<[u8; 32], ProvisioningRunError> {
    let mut writer = rka_protocol::CborWriter::with_capacity(4096);
    writer.array(chains.len());
    for chain in chains {
        let certificates = crate::provisioning_io::decode_der_chain(chain)
            .map_err(|_| ProvisioningRunError::Validation)?;
        writer.array(certificates.len());
        for certificate in certificates {
            writer.bytes(&certificate);
        }
    }
    Ok(rka_protocol::hash_cbor(
        rka_protocol::HashDomain::ChainSet,
        &writer.finish(),
    ))
}

fn unix_seconds() -> Result<u64, ProvisioningRunError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProvisioningRunError::Configuration)
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rka_rkp::{
        challenge::SignedCertificateResponse,
        config::{BaseUrl, ProvisioningInfo},
        outcome::DurableResponseJournal,
    };

    use super::{
        FileStateStore, ProductionConfig, RoleExecutor, SidecarRole, attempt_identity,
        encode_durable_response, post_with_recovery,
    };

    #[test]
    fn production_post_path_replays_exact_durable_response_without_http() {
        let root = unique_root();
        let config = ProductionConfig {
            socket: root.join("broker.sock"),
            state_root: root.clone(),
            validator_key: root.join("validator.pk8"),
            base: BaseUrl::parse("https://example.test").unwrap(),
            info: ProvisioningInfo::new("fixture", 1, 3).unwrap(),
            fingerprint: "fixture".to_owned(),
            epoch: 1,
            key_count: 1,
        };
        let identity = attempt_identity((7, [2; 16]), (&[3; 16], &[4; 32]), &[[5; 32]]).unwrap();
        let durable =
            encode_durable_response("00000000-0000-4000-8000-000000000001", b"response").unwrap();
        DurableResponseJournal::new(&FileStateStore::new(&root))
            .record_validated(&identity, &durable)
            .unwrap();
        let calls = Cell::new(0_usize);
        let result = post_with_recovery(
            (&config, &RoleExecutor::new(SidecarRole::Donor)),
            &identity,
            || -> Result<SignedCertificateResponse, rka_rkp::ClientError> {
                calls.set(calls.get().saturating_add(1));
                Err(rka_rkp::ClientError::Transport)
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(
            result,
            (
                "00000000-0000-4000-8000-000000000001".to_owned(),
                b"response".to_vec()
            )
        );
    }

    fn unique_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rka-task19-{}-{nonce}", process::id()))
    }
}
