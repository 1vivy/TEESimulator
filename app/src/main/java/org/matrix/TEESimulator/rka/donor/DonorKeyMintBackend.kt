package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.matrix.TEESimulator.attestation.ATTESTATION_OID
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalRecord
import org.matrix.TEESimulator.rka.journal.RkpJournalState
import org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle

data class DonorGenerateRequest(
    val aliasHandle: DonorKeyHandle,
    val rkpHandle: RkpOpaqueHandle,
    val rkpChain: List<ByteArray>,
    val challenge: ByteArray,
    val aaid: ByteArray,
    val transcript: ByteArray,
) {
    init {
        require(rkpChain.size in 2..20)
        require(rkpChain.all { it.size in 1..65_536 })
        require(rkpChain.sumOf(ByteArray::size) <= 524_288)
        require(challenge.size in 16..64)
        require(aaid.isNotEmpty() && aaid.size <= 131_072)
        require(transcript.size in 1..1_048_576)
    }
}

sealed class DonorResult<out T> {
    data class Success<T>(val value: T) : DonorResult<T>()

    data class Failure(val code: DonorError) : DonorResult<Nothing>()
}

enum class DonorError {
    INVALID_REQUEST,
    CAPACITY,
    STALE_HANDLE,
    QUARANTINED,
    OPERATION_LOST,
}

class DonorPublicKey
internal constructor(
    val handle: DonorKeyHandle,
    val publicSpki: DonorPublicBytes,
    val certificateChain: List<DonorPublicBytes>,
    val characteristics: DonorKeyCharacteristics,
    val transcriptSignature: DonorPublicBytes,
)

data class DonorBeginResult(val handle: DonorOperationHandle, val maxChunkBytes: Int = 65_536)

data class DonorUpdateResult(val consumed: Int, val output: DonorPublicBytes)

data class DonorFinishResult(val signature: DonorPublicBytes)

data class DonorDeleteResult(val deleted: Boolean)

data class DonorAbortResult(val aborted: Boolean)

private class RetainedApplicationKey(
    val handle: DonorKeyHandle,
    val keyBlob: ByteArray,
    val leaf: X509Certificate,
    val chain: List<ByteArray>,
    val characteristics: DonorKeyCharacteristics,
    val transcriptSignature: ByteArray,
)

class DonorKeyMintBackend
internal constructor(
    private val device: DonorKeyMintDevice,
    private val journal: RkpJournal,
    private val random: SecureRandom = SecureRandom(),
) {
    private val keys = linkedMapOf<String, RetainedApplicationKey>()
    private var liveOperation: LiveDonorOperation? = null

    @Synchronized
    fun reconcile() {
        val record = journal.recover() ?: return
        if (
            record.state == RkpJournalState.APP_KEY_RECORDED ||
                record.state == RkpJournalState.EXPOSED
        ) {
            keys.clear()
            journal.quarantineCurrent()
        }
    }

    @Synchronized
    fun generate(request: DonorGenerateRequest): DonorResult<DonorPublicKey> {
        val certified = journal.recover() ?: return failure(DonorError.STALE_HANDLE)
        if (certified.state != RkpJournalState.RKP_CERTIFIED) {
            generateFailure("JOURNAL_NOT_CERTIFIED")
            return failure(DonorError.QUARANTINED)
        }
        if (keys.containsKey(request.aliasHandle.key())) return failure(DonorError.STALE_HANDLE)
        val rkpCertificate =
            validateCertifiedChain(certified, request)
                ?: run {
                    generateFailure("VALIDATE_CERTIFIED_CHAIN")
                    return quarantine(certified, DonorError.INVALID_REQUEST)
                }
        val generating =
            runCatching { journal.transition(certified, RkpJournalState.APP_KEY_GENERATING) }
                .getOrElse {
                    generateFailure("JOURNAL_GENERATING")
                    return failure(DonorError.QUARANTINED)
                }
        var creation: DonorKeyCreation? = null
        val resolved =
            try {
                journal.withCertifiedBlob(request.rkpHandle) { rkpBlob ->
                    creation =
                        device.generate(
                            DonorKeyParameters.exact(request.challenge, request.aaid),
                            DonorAttestationKey(
                                rkpBlob,
                                rkpCertificate.subjectX500Principal.encoded,
                            ),
                        )
                }
            } catch (error: Exception) {
                generateFailure("DEVICE_GENERATE", error)
                return quarantine(generating, DonorError.QUARANTINED)
            }
        if (!resolved || creation == null) {
            generateFailure("CERTIFIED_BLOB")
            return quarantine(generating, DonorError.STALE_HANDLE)
        }
        val generated = requireNotNull(creation)
        val leaf =
            validateCreation(generated, rkpCertificate, request)
                ?: run {
                    generateFailure("VALIDATE_CREATION")
                    return deleteAndQuarantine(generating, generated.keyBlob)
                }
        val retained =
            RetainedApplicationKey(
                request.aliasHandle,
                generated.keyBlob.copyOf(),
                leaf,
                listOf(leaf.encoded) + request.rkpChain.map(ByteArray::copyOf),
                generated.characteristics,
                ByteArray(0),
            )
        keys[request.aliasHandle.key()] = retained
        val recorded =
            runCatching { journal.transition(generating, RkpJournalState.APP_KEY_RECORDED) }
                .getOrElse {
                    generateFailure("JOURNAL_RECORDED")
                    keys.remove(request.aliasHandle.key())
                    runCatching { device.delete(retained.keyBlob) }
                    return quarantine(generating, DonorError.QUARANTINED)
                }
        val transcriptSignature =
            signAndVerify(retained, request.transcript)
                ?: run {
                    keys.remove(request.aliasHandle.key())
                    runCatching { device.delete(retained.keyBlob) }
                    journal.quarantineCurrent()
                    return failure(DonorError.QUARANTINED)
                }
        val exposedKey =
            RetainedApplicationKey(
                retained.handle,
                retained.keyBlob,
                retained.leaf,
                retained.chain,
                retained.characteristics,
                transcriptSignature,
            )
        keys[request.aliasHandle.key()] = exposedKey
        runCatching { journal.transition(recorded, RkpJournalState.EXPOSED) }
            .getOrElse {
                generateFailure("JOURNAL_EXPOSED")
                keys.remove(request.aliasHandle.key())
                runCatching { device.delete(retained.keyBlob) }
                journal.quarantineCurrent()
                return failure(DonorError.QUARANTINED)
            }
        return DonorResult.Success(exposedKey.publicResult())
    }

    private fun generateFailure(stage: String, error: Throwable? = null) {
        val type = error?.javaClass?.simpleName ?: "NONE"
        SystemLogger.warning("RKA donor generate failed: stage=$stage type=$type")
    }

    @Synchronized
    fun get(handle: DonorKeyHandle): DonorResult<DonorPublicKey> =
        keys[handle.key()]?.let { DonorResult.Success(it.publicResult()) }
            ?: failure(DonorError.STALE_HANDLE)

    @Synchronized fun list(): List<DonorKeyHandle> = keys.values.map(RetainedApplicationKey::handle)

    @Synchronized
    fun delete(handle: DonorKeyHandle): DonorResult<DonorDeleteResult> {
        if (liveOperation?.key == handle) {
            runCatching { liveOperation?.endpoint?.abort() }
            liveOperation = null
        }
        val key = keys.remove(handle.key()) ?: return failure(DonorError.STALE_HANDLE)
        return try {
            device.delete(key.keyBlob)
            var current = requireNotNull(journal.recover())
            if (current.state == RkpJournalState.EXPOSED) {
                current = journal.transition(current, RkpJournalState.TERMINAL)
            }
            if (current.state == RkpJournalState.TERMINAL) {
                journal.transition(current, RkpJournalState.DELETE)
            }
            key.keyBlob.fill(0)
            DonorResult.Success(DonorDeleteResult(true))
        } catch (_: Exception) {
            journal.quarantineCurrent()
            failure(DonorError.QUARANTINED)
        }
    }

    @Synchronized
    fun begin(handle: DonorKeyHandle): DonorResult<DonorBeginResult> {
        if (liveOperation != null) return failure(DonorError.CAPACITY)
        val key = keys[handle.key()] ?: return failure(DonorError.STALE_HANDLE)
        return try {
            val operationHandle = DonorOperationHandle.fresh(random)
            liveOperation = LiveDonorOperation(operationHandle, handle, device.begin(key.keyBlob))
            DonorResult.Success(DonorBeginResult(operationHandle))
        } catch (_: Exception) {
            operationFailure(key)
        }
    }

    @Synchronized
    fun updateAad(handle: DonorOperationHandle, input: ByteArray): DonorResult<DonorUpdateResult> {
        if (input.size > 65_536) return failure(DonorError.INVALID_REQUEST)
        val operation = operation(handle) ?: return failure(DonorError.OPERATION_LOST)
        return try {
            operation.endpoint.updateAad(input)
            DonorResult.Success(DonorUpdateResult(input.size, DonorPublicBytes.of(ByteArray(0))))
        } catch (_: Exception) {
            operationFailure(keys[operation.key.key()])
        }
    }

    @Synchronized
    fun update(handle: DonorOperationHandle, input: ByteArray): DonorResult<DonorUpdateResult> {
        if (input.size > 65_536) return failure(DonorError.INVALID_REQUEST)
        val operation = operation(handle) ?: return failure(DonorError.OPERATION_LOST)
        return try {
            val output = operation.endpoint.update(input)
            operation.append(input)
            DonorResult.Success(DonorUpdateResult(input.size, DonorPublicBytes.of(output)))
        } catch (_: Exception) {
            operationFailure(keys[operation.key.key()])
        }
    }

    @Synchronized
    fun finish(handle: DonorOperationHandle, input: ByteArray): DonorResult<DonorFinishResult> {
        if (input.size > 65_536) return failure(DonorError.INVALID_REQUEST)
        val operation = operation(handle) ?: return failure(DonorError.OPERATION_LOST)
        val key = keys[operation.key.key()] ?: return failure(DonorError.STALE_HANDLE)
        return try {
            val signature = operation.endpoint.finish(input)
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key.leaf.publicKey)
            verifier.update(operation.completeInput(input))
            if (!verifier.verify(signature)) throw IllegalArgumentException("signature")
            liveOperation = null
            DonorResult.Success(DonorFinishResult(DonorPublicBytes.of(signature)))
        } catch (_: Exception) {
            operationFailure(key)
        }
    }

    @Synchronized
    fun abort(handle: DonorOperationHandle): DonorResult<DonorAbortResult> {
        val operation = operation(handle) ?: return failure(DonorError.OPERATION_LOST)
        return try {
            operation.endpoint.abort()
            liveOperation = null
            DonorResult.Success(DonorAbortResult(true))
        } catch (_: Exception) {
            operationFailure(keys[operation.key.key()])
        }
    }

    @Synchronized
    fun binderDied() {
        liveOperation = null
        keys.values.forEach { it.keyBlob.fill(0) }
        keys.clear()
        journal.quarantineCurrent()
    }

    @Synchronized
    fun peerDied() {
        val operation = liveOperation ?: return
        operationFailure(keys[operation.key.key()])
    }

    private fun validateCertifiedChain(
        certified: RkpJournalRecord,
        request: DonorGenerateRequest,
    ): X509Certificate? {
        val key =
            certified.certification?.keys?.singleOrNull { it.handle.matches(request.rkpHandle) }
                ?: return null
        val encoded = request.rkpChain.fold(ByteArray(0), ByteArray::plus)
        if (
            !MessageDigest.getInstance("SHA-256").digest(encoded).contentEquals(key.copyChainHash())
        ) {
            return null
        }
        if (request.rkpChain.size != key.certificateCount) return null
        val certificate = parseCertificate(request.rkpChain.first()) ?: return null
        if (
            !MessageDigest.getInstance("SHA-256")
                .digest(certificate.publicKey.encoded)
                .contentEquals(key.copySpkiHash())
        ) {
            return null
        }
        return certificate
    }

    private fun validateCreation(
        creation: DonorKeyCreation,
        issuer: X509Certificate,
        request: DonorGenerateRequest,
    ): X509Certificate? {
        if (creation.keyBlob.isEmpty()) return null
        if (creation.characteristics != DonorKeyCharacteristics.exact()) return null
        if (creation.certificateChain.size != 1) return null
        val leaf = parseCertificate(creation.certificateChain.single()) ?: return null
        if (leaf.issuerX500Principal != issuer.subjectX500Principal) return null
        if (runCatching { leaf.verify(issuer.publicKey) }.isFailure) return null
        val publicKey = leaf.publicKey as? ECPublicKey ?: return null
        if (publicKey.params.curve.field.fieldSize != 256) return null
        val attestation = parseAttestation(leaf) ?: return null
        if (!attestation.first.contentEquals(request.challenge)) return null
        if (!attestation.second.contentEquals(request.aaid)) return null
        return leaf
    }

    private fun signAndVerify(key: RetainedApplicationKey, transcript: ByteArray): ByteArray? {
        var stage = "TRANSCRIPT_BEGIN"
        return try {
            val operation = device.begin(key.keyBlob)
            stage = "TRANSCRIPT_UPDATE"
            operation.update(transcript)
            stage = "TRANSCRIPT_FINISH"
            val signature = operation.finish(ByteArray(0))
            stage = "TRANSCRIPT_VERIFIER"
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key.leaf.publicKey)
            verifier.update(transcript)
            check(verifier.verify(signature))
            signature
        } catch (error: Exception) {
            generateFailure(stage, error)
            null
        } catch (error: LinkageError) {
            generateFailure(stage, error)
            null
        }
    }

    private fun parseAttestation(certificate: X509Certificate): Pair<ByteArray, ByteArray>? =
        runCatching {
                val outer =
                    ASN1OctetString.getInstance(certificate.getExtensionValue(ATTESTATION_OID.id))
                val description = ASN1Sequence.getInstance(outer.octets)
                val challenge =
                    ASN1OctetString.getInstance(
                            description.getObjectAt(
                                AttestationConstants.KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX
                            )
                        )
                        .octets
                val lists =
                    listOf(
                        description.getObjectAt(
                            AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX
                        ),
                        description.getObjectAt(
                            AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX
                        ),
                    )
                val tagged =
                    lists
                        .asSequence()
                        .map(ASN1Sequence::getInstance)
                        .flatMap { it.asSequence() }
                        .filterIsInstance<ASN1TaggedObject>()
                        .single { it.tagNo == AttestationConstants.TAG_ATTESTATION_APPLICATION_ID }
                challenge to ASN1OctetString.getInstance(tagged.baseObject).octets
            }
            .getOrNull()

    private fun parseCertificate(encoded: ByteArray): X509Certificate? =
        runCatching {
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
            }
            .getOrNull()

    private fun operation(handle: DonorOperationHandle): LiveDonorOperation? =
        liveOperation?.takeIf { it.handle.matches(handle) }

    private fun RetainedApplicationKey.publicResult(): DonorPublicKey =
        DonorPublicKey(
            handle,
            DonorPublicBytes.of(leaf.publicKey.encoded),
            chain.map(DonorPublicBytes::of),
            characteristics,
            DonorPublicBytes.of(transcriptSignature),
        )

    private fun deleteAndQuarantine(
        record: RkpJournalRecord,
        keyBlob: ByteArray,
    ): DonorResult.Failure {
        runCatching { device.delete(keyBlob) }
        keyBlob.fill(0)
        return quarantine(record, DonorError.QUARANTINED)
    }

    private fun operationFailure(key: RetainedApplicationKey?): DonorResult.Failure {
        liveOperation = null
        key?.let {
            keys.remove(it.handle.key())
            runCatching { device.delete(it.keyBlob) }
            it.keyBlob.fill(0)
        }
        journal.quarantineCurrent()
        return failure(DonorError.OPERATION_LOST)
    }

    private fun quarantine(record: RkpJournalRecord, code: DonorError): DonorResult.Failure {
        runCatching {
            if (record.state == RkpJournalState.APP_KEY_GENERATING) journal.quarantine(record)
            else journal.quarantineCurrent()
        }
        return failure(code)
    }

    private fun failure(code: DonorError) = DonorResult.Failure(code)
}
