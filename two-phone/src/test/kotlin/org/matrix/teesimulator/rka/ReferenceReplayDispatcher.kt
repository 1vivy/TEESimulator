package org.matrix.teesimulator.rka

import java.security.MessageDigest

data class DispatchResult(val error: ErrorCode, val response: ByteArray?)

class ReferenceReplayDispatcher(
    private val activeEpoch: ULong,
    private val activeSessionId: ByteArray,
    private val activeTransport: TransportKind,
    private val sessionEstablishedUnixMillis: ULong,
) {
    private data class ReplayIdentity(
        val profileEpoch: ULong,
        val sessionId: String,
        val requestId: String,
    )

    private data class ReplayRecord(val fingerprint: ByteArray, val response: ByteArray)

    private val replayRecords = mutableMapOf<ReplayIdentity, ReplayRecord>()
    private var nextSequence: ULong = 1u
    private var requestCount = 0
    private var operationInputBytes = 0
    private var operationIsLive = false

    var backendExecutionCount: Int = 0
        private set

    fun dispatch(encoded: ByteArray): DispatchResult {
        val request = RkaReferenceCodec.decode(encoded)
        require(request.kind == MessageKind.REQUEST)
        if (
            request.profileEpoch != activeEpoch || !request.sessionId.contentEquals(activeSessionId)
        ) {
            return DispatchResult(ErrorCode.OLD_SESSION, null)
        }
        if (request.transport != activeTransport) {
            return DispatchResult(ErrorCode.TRANSPORT_MISMATCH, null)
        }
        val identity =
            ReplayIdentity(
                request.profileEpoch,
                request.sessionId.toHexString(),
                request.requestId.toHexString(),
            )
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(encoded)
        replayRecords[identity]?.let { record ->
            return if (record.fingerprint.contentEquals(fingerprint)) {
                DispatchResult(ErrorCode.OK, record.response.copyOf())
            } else {
                DispatchResult(ErrorCode.REPLAY_CONFLICT, null)
            }
        }
        if (requestCount >= RkaLimits.REQUESTS_PER_SESSION) {
            return DispatchResult(ErrorCode.REQUEST_LIMIT, null)
        }
        if (request.sequence != nextSequence) {
            return DispatchResult(ErrorCode.SEQUENCE_ERROR, null)
        }
        val maximumDeadline =
            sessionEstablishedUnixMillis + RkaLimits.DEADLINE_SECONDS.toULong() * 1_000u
        if (
            request.deadlineUnixMillis < sessionEstablishedUnixMillis ||
                request.deadlineUnixMillis > maximumDeadline
        ) {
            return DispatchResult(ErrorCode.DEADLINE_EXCEEDED, null)
        }
        val backendError = executeMethod(RkaPayloadCodec.decode(request))
        backendExecutionCount += 1
        requestCount += 1
        nextSequence += 2u
        val response =
            RkaReferenceCodec.encode(
                request.copy(
                    kind = MessageKind.RESPONSE,
                    error = backendError,
                    sequence = request.sequence + 1u,
                    payload =
                        if (backendError == ErrorCode.OK) {
                            GoldenVectorFixtures.responsePayload(request.method)
                        } else {
                            byteArrayOf()
                        },
                )
            )
        replayRecords[identity] = ReplayRecord(fingerprint, response)
        return DispatchResult(backendError, response.copyOf())
    }

    private fun executeMethod(payload: RkaPayload?): ErrorCode =
        when (payload) {
            is BeginRequest ->
                if (operationIsLive) {
                    ErrorCode.OPERATION_ALREADY_LIVE
                } else {
                    operationIsLive = true
                    operationInputBytes = 0
                    ErrorCode.OK
                }
            is UpdateRequest -> consumeOperationInput(payload.input.size, terminal = false)
            is FinishRequest -> consumeOperationInput(payload.input.size, terminal = true)
            is AbortRequest ->
                if (operationIsLive) {
                    operationIsLive = false
                    ErrorCode.OK
                } else {
                    ErrorCode.INVALID_OPERATION_HANDLE
                }
            is GenerateRequest,
            is GetMetadataRequest,
            is DeleteRequest -> ErrorCode.OK
            is GenerateResponse,
            is GetMetadataResponse,
            is DeleteResponse,
            is BeginResponse,
            is UpdateResponse,
            is FinishResponse,
            is AbortResponse,
            null -> error("request payload required")
        }

    private fun consumeOperationInput(size: Int, terminal: Boolean): ErrorCode {
        if (!operationIsLive) return ErrorCode.INVALID_OPERATION_HANDLE
        if (operationInputBytes + size > RkaLimits.OPERATION_INPUT_BYTES) {
            return ErrorCode.INPUT_TOO_LARGE
        }
        operationInputBytes += size
        if (terminal) operationIsLive = false
        return ErrorCode.OK
    }
}
