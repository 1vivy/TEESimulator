package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID

data class WireCallerIdentity(
    val signingCertificateDigest: String,
    val attestationApplicationIdDigest: String,
) {
    companion object {
        fun from(caller: CallerIdentity) =
            WireCallerIdentity(
                caller.signingCertificateDigest,
                caller.attestationApplicationIdDigest,
            )
    }
}

class WireKeyHandle(val id: UUID, binding: ByteArray) {
    private val bindingBytes = binding.copyOf()

    val binding: ByteArray
        get() = bindingBytes.copyOf()
}

class WireOperationHandle(val id: UUID, val keyId: UUID, binding: ByteArray) {
    private val bindingBytes = binding.copyOf()

    val binding: ByteArray
        get() = bindingBytes.copyOf()
}

enum class WireKeyAlgorithm {
    EC
}

enum class WireEcCurve {
    P256
}

enum class WireDigest {
    SHA256
}

enum class WireKeyPurpose {
    SIGN
}

data class WireKeySpec(
    val algorithm: WireKeyAlgorithm,
    val curve: WireEcCurve,
    val digest: WireDigest,
    val purpose: WireKeyPurpose,
)

data class WireOperationSpec(val purpose: WireKeyPurpose, val digest: WireDigest)

class WireKeyMetadata(
    val state: KeyState,
    attestationChallenge: ByteArray,
    publicKey: ByteArray,
    certificateChain: List<ByteArray>,
    val keySpec: WireKeySpec,
) {
    private val challengeBytes = attestationChallenge.copyOf()
    private val publicKeyBytes = publicKey.copyOf()
    private val certificateBytes = certificateChain.map(ByteArray::copyOf)

    val attestationChallenge: ByteArray
        get() = challengeBytes.copyOf()

    val publicKey: ByteArray
        get() = publicKeyBytes.copyOf()

    val certificateChain: List<ByteArray>
        get() = certificateBytes.map(ByteArray::copyOf)
}

sealed interface LifecycleRequestPayload {
    val method: Method
}

class GenerateRequestPayload(
    val generationId: UUID,
    logicalNameHash: ByteArray,
    challenge: ByteArray,
    val keySpec: WireKeySpec,
) : LifecycleRequestPayload {
    private val logicalNameHashBytes = logicalNameHash.copyOf()
    private val challengeBytes = challenge.copyOf()

    override val method = Method.GENERATE

    val logicalNameHash: ByteArray
        get() = logicalNameHashBytes.copyOf()

    val challenge: ByteArray
        get() = challengeBytes.copyOf()
}

object ImportRequestPayload : LifecycleRequestPayload {
    override val method = Method.IMPORT
}

class GetMetadataRequestPayload(val handle: WireKeyHandle) : LifecycleRequestPayload {
    override val method = Method.GET_METADATA
}

class DeleteRequestPayload(val deletionId: UUID, val handle: WireKeyHandle) :
    LifecycleRequestPayload {
    override val method = Method.DELETE
}

class BeginRequestPayload(
    val operationId: UUID,
    val step: ULong,
    val handle: WireKeyHandle,
    val operationSpec: WireOperationSpec,
) : LifecycleRequestPayload {
    override val method = Method.BEGIN
}

class UpdateAadRequestPayload(
    val operation: WireOperationHandle,
    val step: ULong,
    input: ByteArray,
) : LifecycleRequestPayload {
    private val inputBytes = input.copyOf()

    override val method = Method.UPDATE_AAD

    val input: ByteArray
        get() = inputBytes.copyOf()
}

class UpdateRequestPayload(val operation: WireOperationHandle, val step: ULong, input: ByteArray) :
    LifecycleRequestPayload {
    private val inputBytes = input.copyOf()

    override val method = Method.UPDATE

    val input: ByteArray
        get() = inputBytes.copyOf()
}

class FinishRequestPayload(val operation: WireOperationHandle, val step: ULong, input: ByteArray) :
    LifecycleRequestPayload {
    private val inputBytes = input.copyOf()

    override val method = Method.FINISH

    val input: ByteArray
        get() = inputBytes.copyOf()
}

class AbortRequestPayload(val operation: WireOperationHandle, val step: ULong) :
    LifecycleRequestPayload {
    override val method = Method.ABORT
}

sealed interface LifecycleResultPayload {
    val method: Method
}

class GenerateResultPayload(
    val generationId: UUID,
    val handle: WireKeyHandle,
    val metadata: WireKeyMetadata,
) : LifecycleResultPayload {
    override val method = Method.GENERATE
}

class GetMetadataResultPayload(val metadata: WireKeyMetadata) : LifecycleResultPayload {
    override val method = Method.GET_METADATA
}

class DeleteResultPayload(val deletionId: UUID) : LifecycleResultPayload {
    override val method = Method.DELETE
}

class BeginResultPayload(val operation: WireOperationHandle, val step: ULong) :
    LifecycleResultPayload {
    override val method = Method.BEGIN
}

class UpdateAadResultPayload(val step: ULong) : LifecycleResultPayload {
    override val method = Method.UPDATE_AAD
}

class UpdateResultPayload(val step: ULong, output: ByteArray) : LifecycleResultPayload {
    private val outputBytes = output.copyOf()

    override val method = Method.UPDATE

    val output: ByteArray
        get() = outputBytes.copyOf()
}

class FinishResultPayload(val step: ULong, output: ByteArray) : LifecycleResultPayload {
    private val outputBytes = output.copyOf()

    override val method = Method.FINISH

    val output: ByteArray
        get() = outputBytes.copyOf()
}

class AbortResultPayload(val step: ULong) : LifecycleResultPayload {
    override val method = Method.ABORT
}

enum class WireErrorCode {
    UNSUPPORTED_METHOD,
    MALFORMED_REQUEST,
    INVALID_ARGUMENT,
    DEADLINE_EXCEEDED,
    WRONG_SESSION,
    WRONG_CALLER,
    WRONG_PAIR,
    SEQUENCE_ERROR,
    REQUEST_ID_REUSE,
    INVALID_HANDLE,
    INVALID_STATE,
    DONOR_UNAVAILABLE,
    INTERNAL_ERROR,
    REPLAY_CONFLICT,
    INVALID_OPERATION_HANDLE,
}

sealed interface WireOutcome {
    class Success(val payload: LifecycleResultPayload) : WireOutcome

    data class Error(val code: WireErrorCode) : WireOutcome
}

class WireRequestEnvelope(
    val version: ProtocolVersion,
    sessionId: ByteArray,
    clientNonce: ByteArray,
    serverNonce: ByteArray,
    val sequence: ULong,
    val requestId: UUID,
    payloadHash: ByteArray,
    val method: Method,
    val deadline: Instant,
    val caller: WireCallerIdentity,
    val payload: LifecycleRequestPayload,
) {
    private val sessionIdBytes = sessionId.copyOf()
    private val clientNonceBytes = clientNonce.copyOf()
    private val serverNonceBytes = serverNonce.copyOf()
    private val payloadHashBytes = payloadHash.copyOf()

    val sessionId: ByteArray
        get() = sessionIdBytes.copyOf()

    val clientNonce: ByteArray
        get() = clientNonceBytes.copyOf()

    val serverNonce: ByteArray
        get() = serverNonceBytes.copyOf()

    val payloadHash: ByteArray
        get() = payloadHashBytes.copyOf()

    fun copy(method: Method = this.method) =
        WireRequestEnvelope(
            version,
            sessionIdBytes,
            clientNonceBytes,
            serverNonceBytes,
            sequence,
            requestId,
            payloadHashBytes,
            method,
            deadline,
            caller,
            payload,
        )
}

class WireResponseEnvelope(
    val version: ProtocolVersion,
    sessionId: ByteArray,
    val requestId: UUID,
    val method: Method,
    val outcome: WireOutcome,
) {
    private val sessionIdBytes = sessionId.copyOf()

    val sessionId: ByteArray
        get() = sessionIdBytes.copyOf()
}
