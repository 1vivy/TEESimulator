use std::time::{SystemTime, UNIX_EPOCH};

use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use rka_rkp::{
    AttestationStatusClient, BoundedHttpsTransport, ClientError, ExpectedKey, RootBundle,
    ValidationError, assemble_android_v3_body,
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
        BridgeError, BridgeMessage, BrokerBatchId, BrokerCertificationMetadata, BrokerOperation,
        Hash32, PublicBytes, RequestId, RoleExecutor, SidecarRole,
    },
    provision_activation::{ensure_validator_key, prepare},
    provisioning_io::{FileAttemptJournal, FileBaseStore, FileStateStore, ProductionConfig},
};

/// Secret-free activation checkpoints suitable for production diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningActivationStage {
    /// Kernel-random wire request identity creation.
    RequestIdentity,
    /// Attempt identity construction and binding.
    AttemptIdentity,
    /// Durable signed-response replay lookup.
    ResponseReplay,
    /// Durable posting-intent load.
    PostingLoad,
    /// New-attempt comparison with earlier durable material.
    AttemptFreshness,
    /// Durable posting-intent replacement.
    PostingRecord,
    /// Durable validated-response replacement.
    ResponseRecord,
    /// Ambiguous-material construction for quarantine.
    QuarantineMaterial,
    /// Durable quarantine recovery.
    QuarantineRecovery,
    /// Cleanup-intent construction.
    CleanupMaterial,
    /// Certified lease and receipt preparation.
    LeasePreparation,
    /// Descriptor-anchored receipt registry opening.
    ReceiptRegistry,
    /// Signed receipt verification and one-shot consumption.
    ReceiptVerification,
    /// Validated certificate-chain persistence.
    LeaseChainPersistence,
    /// Final active-lease commit.
    LeaseCommit,
}

/// Secret-free response-validation checkpoints suitable for production diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningValidationStage {
    /// Android V3 certificate request assembly.
    RequestAssembly,
    /// Durable signed-response envelope encoding.
    DurableResponseEncoding,
    /// Durable signed-response envelope decoding.
    DurableResponseDecoding,
    /// Certificate serial extraction with a redacted validation category.
    ReturnedSerials(ValidationError),
    /// Revocation-status snapshot retrieval with a redacted validation category.
    StatusSnapshot(ValidationError),
    /// Signed certificate response validation with a redacted validation category.
    SignedResponse(ValidationError),
    /// Certificate-chain parsing with a redacted validation category.
    SignedChains(ValidationError),
    /// Canonical chain-set hashing.
    ChainSet,
}

/// Secret-free failure information retained when best-effort cleanup also fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningFailureStage {
    /// Configuration failure.
    Configuration,
    /// Broker response failure.
    Broker,
    /// Authenticated broker transport failure.
    BrokerBridge(BridgeError),
    /// HTTPS client failure.
    Http(ClientError),
    /// Unclassified validation failure.
    Validation,
    /// Classified validation failure.
    ValidationStage(ProvisioningValidationStage),
    /// Unclassified activation failure.
    Activation,
    /// Classified activation failure.
    ActivationStage(ProvisioningActivationStage),
}

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
    /// The authenticated broker transport failed with a redacted bridge category.
    #[error("provisioning broker bridge failed: {0}")]
    BrokerBridge(BridgeError),
    /// Fetch or signing HTTPS failed with a redacted client category.
    #[error("provisioning HTTP failed: {0}")]
    Http(ClientError),
    /// Returned status or certificate validation failed.
    #[error("provisioning validation failed")]
    Validation,
    /// Returned status or certificate validation failed at a redacted checkpoint.
    #[error("provisioning validation failed at {0:?}")]
    ValidationStage(ProvisioningValidationStage),
    /// Signed receipt activation or durable state failed.
    #[error("provisioning activation failed")]
    Activation,
    /// Signed receipt activation or durable state failed at a redacted checkpoint.
    #[error("provisioning activation failed at {0:?}")]
    ActivationStage(ProvisioningActivationStage),
    /// Cleanup failed after a prior failure; both secret-free categories are retained.
    #[error("provisioning cleanup failed after {prior:?}: {cleanup:?}")]
    Cleanup {
        /// The failure that caused cleanup to run.
        prior: ProvisioningFailureStage,
        /// The failure encountered while attempting cleanup.
        cleanup: ProvisioningFailureStage,
    },
}

impl ProvisioningRunError {
    const fn failure_stage(self) -> ProvisioningFailureStage {
        match self {
            Self::Configuration => ProvisioningFailureStage::Configuration,
            Self::Broker => ProvisioningFailureStage::Broker,
            Self::BrokerBridge(error) => ProvisioningFailureStage::BrokerBridge(error),
            Self::Http(error) => ProvisioningFailureStage::Http(error),
            Self::Validation => ProvisioningFailureStage::Validation,
            Self::ValidationStage(stage) => ProvisioningFailureStage::ValidationStage(stage),
            Self::Activation => ProvisioningFailureStage::Activation,
            Self::ActivationStage(stage) => ProvisioningFailureStage::ActivationStage(stage),
            Self::Cleanup { prior, .. } => prior,
        }
    }
}

const fn cleanup_failure(
    prior: ProvisioningRunError,
    cleanup: ProvisioningRunError,
) -> ProvisioningRunError {
    ProvisioningRunError::Cleanup {
        prior: prior.failure_stage(),
        cleanup: cleanup.failure_stage(),
    }
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
    let request_id = fresh_request_id()?;
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
        .map_err(ProvisioningRunError::BrokerBridge)?;
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
        let prepared =
            assemble_android_v3_body(hal_csr.as_slice(), &config.fingerprint).map_err(|_| {
                ProvisioningRunError::ValidationStage(ProvisioningValidationStage::RequestAssembly)
            })?;
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
    if let Err(prior) = result {
        if !matches!(prior, ProvisioningRunError::Http(_)) && !broker_handles.is_empty() {
            let batch_id = broker_batch_id.ok_or(ProvisioningRunError::Activation)?;
            if let Err(cleanup) = cancel_generated_batch(
                &executor,
                (&config.socket, request_id),
                (batch_id, &broker_handles),
            ) {
                return Err(cleanup_failure(prior, cleanup));
            }
        }
        return Err(prior);
    }
    Ok(())
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
    let material = AmbiguousMaterial::new(request, batch_id, handles.to_vec()).map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::CleanupMaterial)
    })?;
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
        .map_err(ProvisioningRunError::BrokerBridge)?;
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
    .map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::AttemptIdentity)
    })
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
        Err(_) => {
            return Err(ProvisioningRunError::ActivationStage(
                ProvisioningActivationStage::ResponseReplay,
            ));
        }
    }
    let posting = DurablePostingJournal::new(&store);
    if let Some(previous) = posting.load().map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::PostingLoad)
    })? {
        if previous == *identity {
            quarantine(config, executor, &previous)?;
            return Err(ProvisioningRunError::Http(ClientError::PostAmbiguous));
        }
        validate_fresh_attempt(&previous, identity).map_err(|_| {
            ProvisioningRunError::ActivationStage(ProvisioningActivationStage::AttemptFreshness)
        })?;
        match responses.replay_for(&previous) {
            Ok(Some(_)) => {}
            Ok(None) | Err(OutcomeError::StaleReplay) => quarantine(config, executor, &previous)?,
            Err(_) => {
                return Err(ProvisioningRunError::ActivationStage(
                    ProvisioningActivationStage::ResponseReplay,
                ));
            }
        }
    }
    posting.record(identity).map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::PostingRecord)
    })?;
    match post() {
        Ok(signed) => {
            let durable = encode_durable_response(signed.request_id(), signed.response().body())?;
            responses
                .record_validated(identity, &durable)
                .map_err(|_| {
                    ProvisioningRunError::ActivationStage(
                        ProvisioningActivationStage::ResponseRecord,
                    )
                })?;
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
        return Err(ProvisioningRunError::ValidationStage(
            ProvisioningValidationStage::DurableResponseEncoding,
        ));
    }
    let mut durable = Vec::with_capacity(37_usize.saturating_add(response.len()));
    durable.extend_from_slice(request_id.as_bytes());
    durable.push(b'\n');
    durable.extend_from_slice(response);
    Ok(durable)
}

fn decode_durable_response(durable: &[u8]) -> Result<(String, Vec<u8>), ProvisioningRunError> {
    let failure = || {
        ProvisioningRunError::ValidationStage(ProvisioningValidationStage::DurableResponseDecoding)
    };
    let request = durable.get(..36).ok_or_else(failure)?;
    if durable.get(36) != Some(&b'\n') {
        return Err(failure());
    }
    let request = std::str::from_utf8(request).map_err(|_| failure())?;
    let response = durable.get(37..).ok_or_else(failure)?.to_vec();
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
    .map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::QuarantineMaterial)
    })?;
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
        .map_err(|_| {
            ProvisioningRunError::ActivationStage(ProvisioningActivationStage::QuarantineRecovery)
        })
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
    clippy::too_many_lines,
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
    let serials = returned_serials(response, expected.len()).map_err(|error| {
        ProvisioningRunError::ValidationStage(ProvisioningValidationStage::ReturnedSerials(error))
    })?;
    let mut status = AttestationStatusClient::new(
        BoundedHttpsTransport::new().map_err(ProvisioningRunError::Http)?,
    );
    let snapshot = status
        .snapshot_for(now, serials.iter().map(String::as_str))
        .map_err(|error| {
            ProvisioningRunError::ValidationStage(ProvisioningValidationStage::StatusSnapshot(
                error,
            ))
        })?;
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
    .map_err(|error| {
        ProvisioningRunError::ValidationStage(ProvisioningValidationStage::SignedResponse(error))
    })?;
    let encoded_chains =
        rka_rkp::parse_signed_certificates(response, expected.len()).map_err(|error| {
            ProvisioningRunError::ValidationStage(ProvisioningValidationStage::SignedChains(error))
        })?;
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
        .map_err(ProvisioningRunError::BrokerBridge)?;
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
        .map_err(|_| {
            ProvisioningRunError::ActivationStage(
                ProvisioningActivationStage::LeaseChainPersistence,
            )
        })?;
    prepared_activation.activate(&FileStateStore::new(&config.state_root))?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    value
}

fn fresh_request_id() -> Result<u64, ProvisioningRunError> {
    let mut bytes = [0_u8; 8];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        ProvisioningRunError::ActivationStage(ProvisioningActivationStage::RequestIdentity)
    })?;
    Ok(request_id_from_bytes(bytes))
}

const fn request_id_from_bytes(bytes: [u8; 8]) -> u64 {
    u64::from_be_bytes(bytes)
}

fn chain_set_hash(chains: &[Vec<u8>]) -> Result<[u8; 32], ProvisioningRunError> {
    let mut writer = rka_protocol::CborWriter::with_capacity(4096);
    writer.array(chains.len());
    for chain in chains {
        let certificates = crate::provisioning_io::decode_der_chain(chain).map_err(|_| {
            ProvisioningRunError::ValidationStage(ProvisioningValidationStage::ChainSet)
        })?;
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
        FileStateStore, ProductionConfig, ProvisioningActivationStage, ProvisioningFailureStage,
        ProvisioningRunError, ProvisioningValidationStage, RoleExecutor, SidecarRole,
        attempt_identity, cleanup_failure, encode_durable_response, post_with_recovery,
    };

    #[test]
    fn broker_bridge_failure_preserves_only_the_redacted_category() {
        let error = ProvisioningRunError::BrokerBridge(crate::bridge::BridgeError::PeerIdentity);

        assert_eq!(format!("{error:?}"), "BrokerBridge(PeerIdentity)");
        assert_eq!(
            error.to_string(),
            "provisioning broker bridge failed: bridge peer identity rejected"
        );
    }

    #[test]
    fn cleanup_failure_preserves_the_original_redacted_stage() {
        let error = cleanup_failure(
            ProvisioningRunError::ActivationStage(ProvisioningActivationStage::PostingRecord),
            ProvisioningRunError::BrokerBridge(crate::bridge::BridgeError::PeerDied),
        );

        assert_eq!(
            error,
            ProvisioningRunError::Cleanup {
                prior: ProvisioningFailureStage::ActivationStage(
                    ProvisioningActivationStage::PostingRecord,
                ),
                cleanup: ProvisioningFailureStage::BrokerBridge(
                    crate::bridge::BridgeError::PeerDied,
                ),
            }
        );
        assert_eq!(
            format!("{error:?}"),
            "Cleanup { prior: ActivationStage(PostingRecord), cleanup: BrokerBridge(PeerDied) }"
        );
    }

    #[test]
    fn validation_failure_exposes_only_a_stable_checkpoint() {
        let error = ProvisioningRunError::ValidationStage(
            ProvisioningValidationStage::SignedResponse(rka_rkp::ValidationError::Spki),
        );

        assert_eq!(
            format!("{error:?}"),
            "ValidationStage(SignedResponse(Spki))"
        );
        assert_eq!(
            error.to_string(),
            "provisioning validation failed at SignedResponse(Spki)"
        );
    }

    #[test]
    fn request_id_uses_all_kernel_entropy_bytes_in_wire_order() {
        assert_eq!(
            super::request_id_from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
            0x0102_0304_0506_0708,
        );
        assert_ne!(super::request_id_from_bytes([0; 8]), 1);
    }

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
