package org.matrix.teesimulator.rka

enum class MessageKind(val tag: Int) {
    REQUEST(1),
    RESPONSE(2);

    companion object {
        fun fromTag(tag: Int): MessageKind = entries.single { it.tag == tag }
    }
}

enum class TransportKind(val tag: Int) {
    DIRECT_PINNED_TLS(1),
    DIAGNOSTIC_USB_RELAY(2);

    companion object {
        fun fromTag(tag: Int): TransportKind = entries.single { it.tag == tag }
    }
}

enum class Method(val tag: Int) {
    GENERATE(1),
    GET_METADATA(2),
    DELETE(3),
    BEGIN(4),
    UPDATE(5),
    FINISH(6),
    ABORT(7);

    companion object {
        fun fromTag(tag: Int): Method = entries.single { it.tag == tag }
    }
}

enum class ErrorCode(val tag: Int) {
    OK(0),
    MALFORMED_FRAME(1),
    UNSUPPORTED_VERSION(2),
    FRAME_TOO_LARGE(3),
    FIELD_OUT_OF_RANGE(4),
    AUTH_FAILED(5),
    PEER_PIN_MISMATCH(6),
    TRANSPORT_MISMATCH(7),
    OLD_SESSION(8),
    SEQUENCE_ERROR(9),
    REQUEST_LIMIT(10),
    DEADLINE_EXCEEDED(11),
    REPLAY_CONFLICT(12),
    DONOR_UNAVAILABLE(13),
    KEY_NOT_FOUND(14),
    INVALID_KEY_HANDLE(15),
    INVALID_OPERATION_HANDLE(16),
    OPERATION_ALREADY_LIVE(17),
    INPUT_TOO_LARGE(18),
    ATTESTATION_REJECTED(19),
    RKP_PROVENANCE_UNPROVEN(20),
    BACKEND_ERROR(21),
    CANCELLED(22),
    QUARANTINED(23),
    PROFILE_EPOCH_ROLLBACK(24),
    INTERNAL_ERROR(25);

    companion object {
        fun fromTag(tag: Int): ErrorCode = entries.single { it.tag == tag }
    }
}

data class RkaFrame(
    val kind: MessageKind,
    val transport: TransportKind,
    val method: Method,
    val error: ErrorCode,
    val profileEpoch: ULong,
    val sequence: ULong,
    val deadlineUnixMillis: ULong,
    val sessionId: ByteArray,
    val requestId: ByteArray,
    val clientNonce: ByteArray,
    val serverNonce: ByteArray,
    val candidateTlsPin: ByteArray,
    val peerTlsPin: ByteArray,
    val donorFingerprint: ByteArray,
    val callerUid: UInt,
    val callerIdentityHash: ByteArray,
    val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is RkaFrame &&
            RkaReferenceCodec.encode(this).contentEquals(RkaReferenceCodec.encode(other))

    override fun hashCode(): Int = RkaReferenceCodec.encode(this).contentHashCode()
}

sealed interface RkaPayload

data class GenerateRequest(
    val logicalName: String,
    val attestationChallenge: ByteArray,
    val mutationId: ByteArray,
    val purpose: UByte,
    val digest: UByte,
    val curve: UByte,
) : RkaPayload

data class GenerateResponse(
    val keyHandle: ByteArray,
    val publicKeySpki: ByteArray,
    val certificateChain: List<ByteArray>,
) : RkaPayload

data class GetMetadataRequest(val keyHandle: ByteArray) : RkaPayload

data class GetMetadataResponse(
    val keyHandle: ByteArray,
    val publicKeySpki: ByteArray,
    val certificateChain: List<ByteArray>,
    val lifecycleRevision: ULong,
) : RkaPayload

data class DeleteRequest(val keyHandle: ByteArray, val mutationId: ByteArray) : RkaPayload

data class DeleteResponse(val lifecycleRevision: ULong) : RkaPayload

data class BeginRequest(
    val keyHandle: ByteArray,
    val operationId: ByteArray,
    val purpose: UByte,
    val digest: UByte,
) : RkaPayload

data class BeginResponse(val operationHandle: ByteArray) : RkaPayload

data class UpdateRequest(
    val operationHandle: ByteArray,
    val chunkIndex: UInt,
    val input: ByteArray,
) : RkaPayload

data class UpdateResponse(val output: ByteArray) : RkaPayload

data class FinishRequest(
    val operationHandle: ByteArray,
    val input: ByteArray,
    val signature: ByteArray,
) : RkaPayload

data class FinishResponse(val result: ByteArray) : RkaPayload

data class AbortRequest(val operationHandle: ByteArray) : RkaPayload

data class AbortResponse(val terminalState: UByte) : RkaPayload
