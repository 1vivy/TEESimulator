package org.matrix.TEESimulator.rka.bridge

import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyPurpose
import java.io.ByteArrayInputStream
import java.nio.file.Path
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.atomic.AtomicBoolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.matrix.TEESimulator.attestation.ATTESTATION_OID
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.rka.broker.AttestationChallenge
import org.matrix.TEESimulator.rka.broker.AuthenticatedQuarantineRequest
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.QuarantineController
import org.matrix.TEESimulator.rka.broker.QuarantineReceiptStore
import org.matrix.TEESimulator.rka.broker.QuarantineResult
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.donor.AndroidDonorKeyMintDevice
import org.matrix.TEESimulator.rka.donor.DonorAttestationKey
import org.matrix.TEESimulator.rka.donor.DonorDispatchAdapter
import org.matrix.TEESimulator.rka.donor.DonorKeyMintBackend
import org.matrix.TEESimulator.rka.donor.DonorKeyMintDevice
import org.matrix.TEESimulator.rka.donor.DonorSecretBytes
import org.matrix.TEESimulator.rka.donor.DonorSyntheticLeaseCharacteristics
import org.matrix.TEESimulator.rka.donor.DonorSyntheticLeaseCreation
import org.matrix.TEESimulator.rka.donor.DonorSyntheticLeaseParameters
import org.matrix.TEESimulator.rka.journal.DurableIrpcKeyBatchGenerator
import org.matrix.TEESimulator.rka.journal.FileHalCsrJournal
import org.matrix.TEESimulator.rka.journal.FileQuarantineReceiptRegistry
import org.matrix.TEESimulator.rka.journal.FileRkpJournalStore
import org.matrix.TEESimulator.rka.journal.RkpBatchId
import org.matrix.TEESimulator.rka.journal.RkpCertification
import org.matrix.TEESimulator.rka.journal.RkpCertifiedKey
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalState
import org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle

object DonorProvisioningRuntime {
    private val started = AtomicBoolean()
    private val root = Path.of("/data/adb/teesimulator-rka")
    private val client by lazy(IrpcClient::android)
    private val journal by lazy { RkpJournal(FileRkpJournalStore.production(root)) }
    private val csrJournal by lazy { FileHalCsrJournal(root) }
    private val quarantineReceiptStore by lazy { FileQuarantineReceiptRegistry.production(root) }
    private val donorDevice = lazy { AndroidDonorKeyMintDevice.resolve() }
    private val donorBackend = lazy {
        DonorKeyMintBackend(donorDevice.value, journal).also {
            donorDevice.value.onDeath(it::binderDied)
            it.reconcile()
        }
    }
    private var activeRequestId: RequestId? = null
    private var activeCancellation: BrokerCancellation? = null
    private val quarantineController by lazy {
        buildQuarantineController(
            journal,
            quarantineReceiptStore,
            cancel = {
                activeCancellation?.cancel()
                activeCancellation = null
                activeRequestId = null
            },
            cancelled = { activeRequestId == null && activeCancellation == null },
        )
    }

    internal fun buildQuarantineController(
        journal: RkpJournal,
        receipts: QuarantineReceiptStore,
        cancel: () -> Unit,
        cancelled: () -> Boolean,
    ): QuarantineController =
        QuarantineController(
            exactQuarantine = journal::quarantineHandles,
            cancel = cancel,
            cancelled = cancelled,
            discard = journal::discardRetainedBlob,
            discarded = journal::retainedBlobDiscarded,
            wipe = journal::wipeRetainedBlob,
            wiped = journal::retainedBlobWiped,
            receipts = receipts,
            expectedBatch = { journal.recover()?.batchId?.copyBytes() },
            complete = journal::completeQuarantine,
            requireActiveBatch = true,
        )

    fun initializeLifecycle() {
        if (!started.compareAndSet(false, true)) return
        Thread(
                {
                    while (!Thread.currentThread().isInterrupted) {
                        when (val accepted = BrokerBridgeFactory.acceptDonor(::dispatch)) {
                            is BridgeResult.Success -> accepted.value.close()
                            is BridgeResult.Failure -> {
                                if (donorBackend.isInitialized()) donorBackend.value.peerDied()
                                SystemLogger.warning(
                                    "RKA donor bridge exchange failed: ${accepted.error}"
                                )
                                Thread.sleep(100)
                            }
                        }
                    }
                },
                "rka-donor-broker",
            )
            .apply { isDaemon = true }
            .start()
    }

    @Synchronized
    private fun dispatch(message: BridgeMessage): BridgeMessage =
        try {
            dispatchChecked(message)
        } catch (error: Exception) {
            SystemLogger.warning("RKA donor dispatch failed: type=${error.javaClass.simpleName}")
            activeRequestId = null
            activeCancellation = null
            failure(message.requestId)
        }

    private fun dispatchChecked(message: BridgeMessage): BridgeMessage =
        when (message) {
            is BridgeMessage.PublicKeyRequest -> provision(message)
            is BridgeMessage.CertificationRequest -> certify(message)
            is BridgeMessage.CandidateCommand ->
                DonorDispatchAdapter.dispatch(message, donorBackend.value)
            is BridgeMessage.SyntheticLeaseProbeRequest -> {
                donorBackend.value
                probeSyntheticLeaseForTest(message, donorDevice.value, journal)
            }
            is BridgeMessage.Cancel -> {
                val handles = message.brokerHandles()
                val batchId = message.cleanupBatchId()
                val actionIds = message.cleanupActionIds()
                val result =
                    try {
                        quarantineController.quarantine(
                            if (batchId == null) {
                                AuthenticatedQuarantineRequest.fromTrustedBridge(
                                    message.requestId,
                                    handles.map(Hash32::copyBytes),
                                )
                            } else {
                                AuthenticatedQuarantineRequest.fromTrustedBridge(
                                    message.requestId,
                                    handles.map(Hash32::copyBytes),
                                    batchId,
                                    actionIds,
                                )
                            }
                        )
                    } finally {
                        handles.forEach(Hash32::close)
                        batchId?.close()
                        actionIds.forEach(Hash32::close)
                    }
                if (result == QuarantineResult.QUARANTINED) {
                    BridgeMessage.Cancel(message.requestId)
                } else {
                    failure(message.requestId)
                }
            }
            else -> failure(message.requestId)
        }

    private fun provision(request: BridgeMessage.PublicKeyRequest): BridgeMessage {
        var stage = "CHALLENGE"
        return try {
            val challenge =
                AttestationChallenge.parse(request.challenge.copyBytes()) as? BrokerOutcome.Success
                    ?: return failure(request.requestId)
            stage = "JOURNAL_RECOVER"
            if (!journal.prepareForProvisioning()) return failure(request.requestId)
            activeRequestId = null
            activeCancellation = null
            val deadline = BrokerDeadline.at(BridgeLimits.DONOR_DEADLINE_MILLIS)
            val cancellation = BrokerCancellation.active()
            activeCancellation = cancellation
            val generator = DurableIrpcKeyBatchGenerator(client, journal)
            stage = "KEY_COUNT"
            val count =
                RkpKeyCount.parse(request.keyCount) as? BrokerOutcome.Success
                    ?: return failure(request.requestId)
            val generatedOutcome =
                generator.generate(count.value, deadline, cancellation) { stage = it }
            val generated =
                generatedOutcome as? BrokerOutcome.Success
                    ?: return rejected(request.requestId, stage, generatedOutcome)
            val batch = generated.value
            stage = "IRPC_CSR"
            val csrOutcome =
                client.generateCertificateRequest(batch, challenge.value, deadline, cancellation)
            val csr =
                csrOutcome as? BrokerOutcome.Success
                    ?: return rejected(request.requestId, stage, csrOutcome).also {
                        journal.quarantineCurrent()
                    }
            stage = "JOURNAL_RECOVER"
            val record = requireNotNull(journal.recover())
            stage = "CSR_PERSIST"
            runCatching {
                    csrJournal.record(record.batchId, csr.value.copyBytes())
                    journal.transition(record, RkpJournalState.CSR_PREPARED)
                }
                .getOrElse {
                    journal.quarantineCurrent()
                    return failure(request.requestId)
                }
            activeRequestId = request.requestId
            stage = "RESPONSE"
            BridgeMessage.PublicKeyResponse(
                request.requestId,
                PublicBytes.of(csr.value.copyBytes(), BridgeLimits.MAX_FRAME_BYTES),
                BrokerBatchId.of(record.batchId.copyBytes()),
                Hash32.of(record.identity.hash()),
                record.entries.map { entry ->
                    BrokerKeyMetadata(
                        entry.order,
                        Hash32.of(entry.handle.copyBytes()),
                        Hash32.of(entry.copyPublicHash()),
                        Hash32.of(entry.copySpkiHash()),
                    )
                },
            )
        } catch (error: RuntimeException) {
            SystemLogger.warning(
                "RKA donor provisioning failed: stage=$stage type=${error.javaClass.simpleName}"
            )
            failure(request.requestId)
        }
    }

    private fun rejected(
        requestId: RequestId,
        stage: String,
        outcome: BrokerOutcome<*>,
    ): BridgeMessage.Error {
        val type =
            when (outcome) {
                is BrokerOutcome.Failure -> outcome.error.javaClass.simpleName
                BrokerOutcome.SelfCallBypass -> "SelfCallBypass"
                is BrokerOutcome.Success -> "UnexpectedSuccess"
            }
        SystemLogger.warning("RKA donor provisioning rejected: stage=$stage type=$type")
        return failure(requestId)
    }

    private fun certify(request: BridgeMessage.CertificationRequest): BridgeMessage {
        var stage = "MATERIAL"
        val batchBytes = request.batchId.copyBytes()
        val binding = request.activationBindingHash.copyBytes()
        return try {
            stage = "MODEL"
            val keys = request.keyMetadata()
            val certification =
                try {
                    RkpCertification(
                        request.requestId.value,
                        RkpBatchId.from(batchBytes),
                        keys.map {
                            RkpCertifiedKey(
                                it.order,
                                org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle.from(
                                    it.handle.copyBytes()
                                ),
                                it.publicKeyHash.copyBytes(),
                                it.spkiHash.copyBytes(),
                                it.chainHash.copyBytes(),
                                it.certificateCount,
                            )
                        },
                        request.profileEpoch,
                        binding,
                    )
                } finally {
                    keys.forEach(BrokerCertificationMetadata::close)
                }
            stage = "JOURNAL"
            val exact =
                if (activeRequestId == request.requestId) {
                    journal.certifyCurrent(certification)
                } else {
                    journal.quarantineCurrent()
                    false
                }
            activeRequestId = null
            activeCancellation = null
            if (!exact) {
                SystemLogger.warning("RKA donor certification rejected: stage=$stage")
                failure(request.requestId)
            } else {
                stage = "ACK"
                BridgeMessage.CertificationAck(
                    request.requestId,
                    BrokerBatchId.of(batchBytes),
                    Hash32.of(binding),
                )
            }
        } catch (error: Exception) {
            SystemLogger.warning(
                "RKA donor certification failed: stage=$stage " +
                    "type=${error.javaClass.simpleName}"
            )
            activeRequestId = null
            activeCancellation = null
            failure(request.requestId)
        } finally {
            batchBytes.fill(0)
            binding.fill(0)
        }
    }

    private fun failure(requestId: RequestId): BridgeMessage.Error =
        BridgeMessage.Error(requestId, BridgeErrorCode.POLICY_REJECTED, Hash32.of(ByteArray(32)))

    internal fun probeSyntheticLeaseForTest(
        request: BridgeMessage.SyntheticLeaseProbeRequest,
        device: DonorKeyMintDevice,
        targetJournal: RkpJournal,
    ): BridgeMessage {
        val handleBytes = request.rkpHandle.copyBytes()
        val expectedSpki = request.expectedSpki.copyBytes()
        val challenge = request.challenge.copyBytes()
        val aaid = request.aaid.copyBytes()
        val privatePkcs8 = request.privateKeyPkcs8.copyBytes()
        val publicChain = request.certificateChain()
        val rkpChain =
            try {
                publicChain.map(PublicBytes::copyBytes)
            } finally {
                publicChain.forEach(PublicBytes::close)
            }
        var generating: org.matrix.TEESimulator.rka.journal.RkpJournalRecord? = null
        var creation: DonorSyntheticLeaseCreation? = null
        try {
            requireEcP256Pkcs8(privatePkcs8)
            val certified = requireNotNull(targetJournal.recover())
            require(certified.state == RkpJournalState.RKP_CERTIFIED)
            val rkpCertificate = validateCertifiedChain(certified, handleBytes, rkpChain)
            generating = targetJournal.transition(certified, RkpJournalState.APP_KEY_GENERATING)
            val secret =
                DonorSecretBytes.of(privatePkcs8, BridgeLimits.MAX_SYNTHETIC_LEASE_PKCS8_BYTES)
            val resolved =
                secret.use {
                    targetJournal.withCertifiedBlob(RkpOpaqueHandle.from(handleBytes)) { blob ->
                        creation =
                            device.importSyntheticLease(
                                DonorSyntheticLeaseParameters.exact(
                                    challenge,
                                    aaid,
                                    request.certificateNotBeforeMillis,
                                    request.certificateNotAfterMillis,
                                ),
                                it,
                                DonorAttestationKey(
                                    blob,
                                    rkpCertificate.subjectX500Principal.encoded,
                                ),
                            )
                    }
                }
            require(resolved)
            val imported = requireNotNull(creation)
            val canonical =
                validateSyntheticLeaseCreation(
                    imported,
                    expectedSpki,
                    challenge,
                    aaid,
                    rkpChain,
                    rkpCertificate,
                )
            imported.withKeyBlob(device::delete)
            imported.close()
            creation = null
            var record = targetJournal.transition(generating, RkpJournalState.APP_KEY_RECORDED)
            record = targetJournal.transition(record, RkpJournalState.EXPOSED)
            record = targetJournal.transition(record, RkpJournalState.TERMINAL)
            targetJournal.transition(record, RkpJournalState.DELETE)
            val certificates =
                canonical.map { PublicBytes.of(it, BridgeLimits.MAX_CERTIFICATE_BYTES) }
            return try {
                BridgeMessage.SyntheticLeaseProbeResponse(request.requestId, certificates)
            } finally {
                certificates.forEach(PublicBytes::close)
            }
        } catch (error: Exception) {
            creation?.let { imported ->
                runCatching { imported.withKeyBlob(device::delete) }
                imported.close()
            }
            runCatching {
                val current = targetJournal.recover()
                if (current?.state == RkpJournalState.APP_KEY_GENERATING) {
                    targetJournal.quarantine(current)
                } else if (generating != null) {
                    targetJournal.quarantineCurrent()
                }
            }
            throw error
        } finally {
            handleBytes.fill(0)
            expectedSpki.fill(0)
            challenge.fill(0)
            aaid.fill(0)
            privatePkcs8.fill(0)
            rkpChain.forEach { it.fill(0) }
        }
    }

    private fun requireEcP256Pkcs8(privatePkcs8: ByteArray) {
        val key =
            KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privatePkcs8))
                as? ECPrivateKey ?: throw IllegalArgumentException("not an EC private key")
        require(key.params.curve.field.fieldSize == 256)
    }

    private fun validateCertifiedChain(
        record: org.matrix.TEESimulator.rka.journal.RkpJournalRecord,
        handleBytes: ByteArray,
        chain: List<ByteArray>,
    ): X509Certificate {
        val certified =
            requireNotNull(
                record.certification?.keys?.singleOrNull {
                    it.handle.copyBytes().contentEquals(handleBytes)
                }
            )
        require(chain.size == certified.certificateCount)
        val digest = MessageDigest.getInstance("SHA-256")
        chain.forEach(digest::update)
        require(digest.digest().contentEquals(certified.copyChainHash()))
        val certificates = chain.map(::parseCertificateStrict)
        certificates.zipWithNext().forEach { (child, issuer) ->
            require(child.issuerX500Principal == issuer.subjectX500Principal)
            child.verify(issuer.publicKey)
        }
        val root = certificates.last()
        require(root.issuerX500Principal == root.subjectX500Principal)
        root.verify(root.publicKey)
        val rkpCertificate = certificates.first()
        require(
            MessageDigest.getInstance("SHA-256")
                .digest(rkpCertificate.publicKey.encoded)
                .contentEquals(certified.copySpkiHash())
        )
        return rkpCertificate
    }

    private fun validateSyntheticLeaseCreation(
        creation: DonorSyntheticLeaseCreation,
        expectedSpki: ByteArray,
        challenge: ByteArray,
        aaid: ByteArray,
        rkpChain: List<ByteArray>,
        rkpCertificate: X509Certificate,
    ): List<ByteArray> {
        require(creation.characteristics == DonorSyntheticLeaseCharacteristics.exact())
        require(creation.certificateChain.isNotEmpty())
        val leaseCertificate = parseCertificateStrict(creation.certificateChain.first())
        require(leaseCertificate.publicKey is ECPublicKey)
        require((leaseCertificate.publicKey as ECPublicKey).params.curve.field.fieldSize == 256)
        require(leaseCertificate.publicKey.encoded.contentEquals(expectedSpki))
        require(leaseCertificate.issuerX500Principal == rkpCertificate.subjectX500Principal)
        leaseCertificate.verify(rkpCertificate.publicKey)
        leaseCertificate.checkValidity()
        val attestation = parseAttestation(leaseCertificate)
        require(attestation.challenge.contentEquals(challenge))
        require(attestation.aaid.contentEquals(aaid))
        require(attestation.attestationSecurityLevel == 1)
        require(attestation.keyMintSecurityLevel == 1)
        require(attestation.purposes == setOf(KeyPurpose.ATTEST_KEY))
        require(attestation.origin == KeyOrigin.IMPORTED)
        require(attestation.digestCount == 0)
        require(attestation.noAuthRequired)
        if (creation.certificateChain.size > 1) {
            require(creation.certificateChain.drop(1).size == rkpChain.size)
            require(
                creation.certificateChain.drop(1).zip(rkpChain).all { (actual, expected) ->
                    actual.contentEquals(expected)
                }
            )
        }
        return listOf(leaseCertificate.encoded) + rkpChain.map(ByteArray::copyOf)
    }

    private data class ParsedSyntheticAttestation(
        val challenge: ByteArray,
        val aaid: ByteArray,
        val attestationSecurityLevel: Int,
        val keyMintSecurityLevel: Int,
        val purposes: Set<Int>,
        val origin: Int,
        val digestCount: Int,
        val noAuthRequired: Boolean,
    )

    private fun parseAttestation(certificate: X509Certificate): ParsedSyntheticAttestation {
        val outer = ASN1OctetString.getInstance(certificate.getExtensionValue(ATTESTATION_OID.id))
        val description = ASN1Sequence.getInstance(outer.octets)
        val parsedChallenge =
            ASN1OctetString.getInstance(
                    description.getObjectAt(
                        AttestationConstants.KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX
                    )
                )
                .octets
        val tagged =
            listOf(
                    description.getObjectAt(
                        AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX
                    ),
                    description.getObjectAt(AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX),
                )
                .asSequence()
                .map(ASN1Sequence::getInstance)
                .flatMap { it.asSequence() }
                .filterIsInstance<ASN1TaggedObject>()
                .toList()
        val aaid = tagged.single { it.tagNo == AttestationConstants.TAG_ATTESTATION_APPLICATION_ID }
        val purpose = tagged.single { it.tagNo == AttestationConstants.TAG_PURPOSE }
        val purposeSet = ASN1Set.getInstance(purpose.baseObject)
        val purposes =
            (0 until purposeSet.size())
                .map { ASN1Integer.getInstance(purposeSet.getObjectAt(it)).value.toInt() }
                .toSet()
        val origin = tagged.single { it.tagNo == AttestationConstants.TAG_ORIGIN }
        return ParsedSyntheticAttestation(
            parsedChallenge,
            ASN1OctetString.getInstance(aaid.baseObject).octets,
            ASN1Enumerated.getInstance(
                    description.getObjectAt(
                        AttestationConstants.KEY_DESCRIPTION_ATTESTATION_SECURITY_LEVEL_INDEX
                    )
                )
                .value
                .toInt(),
            ASN1Enumerated.getInstance(
                    description.getObjectAt(
                        AttestationConstants.KEY_DESCRIPTION_KEYMINT_SECURITY_LEVEL_INDEX
                    )
                )
                .value
                .toInt(),
            purposes,
            ASN1Integer.getInstance(origin.baseObject).value.toInt(),
            tagged.count { it.tagNo == AttestationConstants.TAG_DIGEST },
            tagged.count { it.tagNo == AttestationConstants.TAG_NO_AUTH_REQUIRED } == 1,
        )
    }

    private fun parseCertificateStrict(encoded: ByteArray): X509Certificate {
        val input = ByteArrayInputStream(encoded)
        val certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        require(input.available() == 0)
        return certificate
    }
}
