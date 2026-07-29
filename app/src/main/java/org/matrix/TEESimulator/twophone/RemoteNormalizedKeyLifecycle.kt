package org.matrix.TEESimulator.twophone

import java.security.MessageDigest
import java.util.UUID
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.matrix.teesimulator.twophone.AbortRequestPayload
import org.matrix.teesimulator.twophone.AbortResultPayload
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.FinishRequestPayload
import org.matrix.teesimulator.twophone.FinishResultPayload
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.GenerateResultPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.LifecycleResultPayload
import org.matrix.teesimulator.twophone.UpdateRequestPayload
import org.matrix.teesimulator.twophone.UpdateResultPayload
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.matrix.teesimulator.twophone.WireOutcome

private const val SHA_256 = "SHA-256"

internal data class RemoteKeyGeneration(
    val logicalName: String,
    val attestationChallenge: ByteArray,
) {
    init {
        require(logicalName.isNotBlank())
        require(attestationChallenge.isNotEmpty())
    }
}

class RemoteGeneratedKey(
    val session: TargetSessionManager,
    val handle: WireKeyHandle,
    val metadata: WireKeyMetadata,
)

internal fun FixturePackageIdentity.toWireCallerIdentity(): WireCallerIdentity {
    val packageSet =
        DERSet(
            arrayOf(
                DERSequence(
                    arrayOf(
                        DEROctetString(packageName.encodeToByteArray()),
                        ASN1Integer(versionCode),
                    )
                )
            )
        )
    val signerSet = DERSet(arrayOf(DEROctetString(signerDigest)))
    val attestationApplicationId = DERSequence(arrayOf(packageSet, signerSet)).encoded
    return WireCallerIdentity(
        MessageDigest.getInstance(SHA_256).digest(signerSet.encoded).hex(),
        MessageDigest.getInstance(SHA_256).digest(attestationApplicationId).hex(),
    )
}

internal class RemoteNormalizedKeyLifecycle(private val session: TargetSessionManager) {
    fun generate(request: RemoteKeyGeneration): RemoteGeneratedKey {
        val generationId = UUID.randomUUID()
        return try {
            val result =
                session
                    .exchange(
                        GenerateRequestPayload(
                            generationId,
                            MessageDigest.getInstance(SHA_256)
                                .digest(request.logicalName.encodeToByteArray()),
                            request.attestationChallenge,
                            KEY_SPEC,
                        )
                    )
                    .expect<GenerateResultPayload>()
            if (result.generationId != generationId) {
                throw TargetSessionException.CorrelationFailure(
                    IllegalStateException("remote generate response did not match its request")
                )
            }
            validateMetadata(result.metadata, request.attestationChallenge)
            RemoteGeneratedKey(session, result.handle, result.metadata)
        } catch (failure: TargetSessionException.CorrelationFailure) {
            session.discardConnection()
            throw failure
        }
    }

    fun begin(key: RemoteGeneratedKey): RemoteSigningOperation {
        if (key.session !== session) {
            throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote key belongs to a different target session")
            )
        }
        val result =
            session
                .exchange(BeginRequestPayload(UUID.randomUUID(), 0uL, key.handle, OPERATION_SPEC))
                .expect<BeginResultPayload>()
        if (result.step != 0uL || result.operation.keyId != key.handle.id) {
            session.abandonOperation(result.operation.id)
            throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote begin response did not bind the generated key")
            )
        }
        return RemoteSigningOperation(session, result.operation)
    }

    private fun validateMetadata(metadata: WireKeyMetadata, challenge: ByteArray) {
        if (
            metadata.state != KeyState.ACTIVE ||
                metadata.keySpec != KEY_SPEC ||
                !MessageDigest.isEqual(metadata.attestationChallenge, challenge) ||
                metadata.publicKey.isEmpty()
        ) {
            throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote generate response failed validation")
            )
        }
    }

    private inline fun <reified T : LifecycleResultPayload> WireOutcome.expect(): T {
        val success =
            this as? WireOutcome.Success
                ?: throw TargetSessionException.RemoteFailure((this as WireOutcome.Error).code)
        return success.payload as? T
            ?: throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote response payload type did not match request")
            )
    }

    private companion object {
        val KEY_SPEC =
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            )
        val OPERATION_SPEC = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)
    }
}

internal class RemoteSigningOperation(
    private val session: TargetSessionManager,
    private val operation: WireOperationHandle,
) {
    private var step = 0uL
    private var active = true

    @Synchronized
    fun update(input: ByteArray): ByteArray =
        exchange<UpdateResultPayload>(step + 1uL) { nextStep ->
                UpdateRequestPayload(operation, nextStep, input)
            }
            .also { result -> step = result.step }
            .output

    @Synchronized
    fun finish(input: ByteArray): ByteArray {
        val result =
            exchange<FinishResultPayload>(step + 1uL) { nextStep ->
                FinishRequestPayload(operation, nextStep, input)
            }
        if (result.output.isEmpty()) {
            abandon()
            throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote finish response did not contain a signature")
            )
        }
        active = false
        return result.output
    }

    @Synchronized
    fun abort() = abort(ownerDeath = false)

    fun abortFromOwnerDeath() {
        if (session.cancelActiveOperation(operation.id)) return
        abort(ownerDeath = true)
    }

    @Synchronized
    private fun abort(ownerDeath: Boolean) {
        if (!active) return
        val nextStep = step + 1uL
        try {
            val result =
                if (ownerDeath) {
                    session.exchangeOwnerDeathAbort(AbortRequestPayload(operation, nextStep))
                } else {
                    session.exchange(AbortRequestPayload(operation, nextStep))
                }
                    .expect<AbortResultPayload>()
            require(result.step == nextStep)
        } finally {
            active = false
            session.abandonOperation(operation.id)
        }
    }

    private inline fun <reified T : LifecycleResultPayload> exchange(
        nextStep: ULong,
        payload: (ULong) -> org.matrix.teesimulator.twophone.LifecycleRequestPayload,
    ): T =
        try {
            check(active)
            val result = session.exchange(payload(nextStep)).expect<T>()
            require(result.step() == nextStep)
            result
        } catch (failure: RuntimeException) {
            abandon()
            throw failure
        }

    private inline fun <reified T : LifecycleResultPayload> WireOutcome.expect(): T {
        val success =
            this as? WireOutcome.Success
                ?: throw TargetSessionException.RemoteFailure((this as WireOutcome.Error).code)
        return success.payload as? T
            ?: throw TargetSessionException.CorrelationFailure(
                IllegalStateException("remote response payload type did not match request")
            )
    }

    private fun abandon() {
        active = false
        session.abandonOperation(operation.id)
    }

    private fun LifecycleResultPayload.step(): ULong =
        when (this) {
            is UpdateResultPayload -> step
            is FinishResultPayload -> step
            is AbortResultPayload -> step
            else ->
                throw TargetSessionException.CorrelationFailure(
                    IllegalStateException("remote operation response did not contain a step")
                )
        }
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
