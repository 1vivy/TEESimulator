package org.matrix.teesimulator.twophone

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

class WireDonorDispatcher
private constructor(
    private val pair: PairIdentity,
    clientNonce: ByteArray,
    serverNonce: ByteArray,
    sessionId: ByteArray,
    private val now: () -> Instant,
    private val backend: WireDonorBackend,
) : AutoCloseable {
    constructor(
        pair: PairIdentity,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        now: () -> Instant,
        backend: WireDonorBackend,
    ) : this(
        pair,
        clientNonce,
        serverNonce,
        deriveSessionId(pair, clientNonce, serverNonce),
        now,
        backend,
    )

    constructor(
        pair: PairIdentity,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        now: () -> Instant,
        rootAdapter: FakeDonorAdapter,
        store: InMemoryWireDonorStore = InMemoryWireDonorStore(),
    ) : this(
        pair,
        clientNonce,
        serverNonce,
        now,
        InMemoryWireDonorBackend(pair, rootAdapter, store),
    )

    private val expectedClientNonce = clientNonce.copyOf()
    private val expectedServerNonce = serverNonce.copyOf()
    private val expectedSessionId = sessionId.copyOf()
    private val sessionMonitor = Any()
    private val requestResponses = mutableMapOf<UUID, CachedSessionResponse>()
    private var nextSequence = 0uL
    private var sequenceExhausted = false
    private val operationMonitor = Any()
    private val operationsByClientId = mutableMapOf<UUID, OperationLedger>()
    private val operationsByDonorId = mutableMapOf<UUID, OperationLedger>()
    private var closed = false

    fun dispatch(request: WireRequestEnvelope): WireResponseEnvelope =
        synchronized(sessionMonitor) {
            if (closed) {
                return@synchronized response(
                    request,
                    WireOutcome.Error(WireErrorCode.DONOR_UNAVAILABLE),
                )
            }
            validateSession(request)?.let {
                return@synchronized response(request, it)
            }
            validatePayload(request)?.let {
                return@synchronized response(request, it)
            }
            validateDeadline(request)?.let {
                return@synchronized response(request, it)
            }

            val fingerprint = requestFingerprint(request)
            requestResponses[request.requestId]?.let { cached ->
                if (!cached.matches(fingerprint)) {
                    return@synchronized response(
                        request,
                        WireOutcome.Error(WireErrorCode.REQUEST_ID_REUSE),
                    )
                }
                return@synchronized cached.response()
            }
            validateAndConsumeSequence(request.sequence)?.let {
                return@synchronized response(request, it)
            }

            val completed = response(request, dispatchValidated(request))
            requestResponses[request.requestId] = CachedSessionResponse(fingerprint, completed)
            completed.defensiveCopy()
        }

    override fun close() {
        synchronized(sessionMonitor) {
            if (closed) return
            closed = true
            synchronized(operationMonitor) {
                operationsByClientId.values.forEach { it.terminal = true }
                operationsByClientId.clear()
                operationsByDonorId.clear()
            }
            runCleanup(backend::close)
        }
    }

    fun forceNextSequenceForTest(value: ULong) {
        synchronized(sessionMonitor) {
            nextSequence = value
            sequenceExhausted = false
        }
    }

    private fun validateSession(request: WireRequestEnvelope): WireOutcome.Error? =
        if (
            !MessageDigest.isEqual(expectedSessionId, request.sessionId) ||
                !MessageDigest.isEqual(expectedClientNonce, request.clientNonce) ||
                !MessageDigest.isEqual(expectedServerNonce, request.serverNonce)
        ) {
            WireOutcome.Error(WireErrorCode.WRONG_SESSION)
        } else {
            null
        }

    private fun validatePayload(request: WireRequestEnvelope): WireOutcome.Error? {
        if (request.method != request.payload.method) {
            return WireOutcome.Error(WireErrorCode.MALFORMED_REQUEST)
        }
        return try {
            if (
                !MessageDigest.isEqual(
                    NormalizedWireCodec.payloadHash(request.payload),
                    request.payloadHash,
                )
            ) {
                WireOutcome.Error(WireErrorCode.MALFORMED_REQUEST)
            } else null
        } catch (_: WireCodecException) {
            WireOutcome.Error(WireErrorCode.MALFORMED_REQUEST)
        }
    }

    private fun validateDeadline(request: WireRequestEnvelope): WireOutcome.Error? {
        val current = now()
        return if (
            current.isAfter(request.deadline) ||
                request.deadline.isAfter(
                    current.plusSeconds(PublicProfileLimits.DEADLINE_SECONDS.toLong())
                )
        ) {
            WireOutcome.Error(WireErrorCode.DEADLINE_EXCEEDED)
        } else {
            null
        }
    }

    private fun validateAndConsumeSequence(sequence: ULong): WireOutcome.Error? {
        if (sequenceExhausted || sequence != nextSequence) {
            return WireOutcome.Error(WireErrorCode.SEQUENCE_ERROR)
        }
        if (sequence == ULong.MAX_VALUE) {
            sequenceExhausted = true
        } else {
            nextSequence++
        }
        return null
    }

    private fun response(request: WireRequestEnvelope, outcome: WireOutcome) =
        WireResponseEnvelope(
            request.version,
            expectedSessionId,
            request.requestId,
            request.method,
            outcome,
        )

    private fun dispatchValidated(request: WireRequestEnvelope): WireOutcome =
        try {
            val payloadHash = NormalizedWireCodec.payloadHash(request.payload)
            when (val payload = request.payload) {
                is GenerateRequestPayload ->
                    WireOutcome.Success(generate(payload, payloadHash, request.caller))
                ImportRequestPayload -> fail(WireErrorCode.UNSUPPORTED_METHOD)
                is GetMetadataRequestPayload ->
                    WireOutcome.Success(metadata(payload, request.caller))
                is DeleteRequestPayload ->
                    WireOutcome.Success(delete(payload, payloadHash, request.caller))
                is BeginRequestPayload ->
                    WireOutcome.Success(begin(payload, payloadHash, request.caller))
                is UpdateAadRequestPayload ->
                    operationStep(
                        payload,
                        payload.operation,
                        payload.step,
                        payloadHash,
                        request.caller,
                    )
                is UpdateRequestPayload ->
                    operationStep(
                        payload,
                        payload.operation,
                        payload.step,
                        payloadHash,
                        request.caller,
                    )
                is FinishRequestPayload ->
                    operationStep(
                        payload,
                        payload.operation,
                        payload.step,
                        payloadHash,
                        request.caller,
                    )
                is AbortRequestPayload ->
                    operationStep(
                        payload,
                        payload.operation,
                        payload.step,
                        payloadHash,
                        request.caller,
                    )
            }
        } catch (failure: DispatchFailure) {
            WireOutcome.Error(failure.code)
        } catch (failure: WireBackendFailure) {
            WireOutcome.Error(failure.code)
        } catch (_: IllegalArgumentException) {
            WireOutcome.Error(WireErrorCode.INVALID_ARGUMENT)
        } catch (_: WireCodecException) {
            WireOutcome.Error(WireErrorCode.MALFORMED_REQUEST)
        } catch (_: RuntimeException) {
            WireOutcome.Error(WireErrorCode.INTERNAL_ERROR)
        }

    private fun generate(
        payload: GenerateRequestPayload,
        payloadHash: ByteArray,
        wireCaller: WireCallerIdentity,
    ): GenerateResultPayload {
        val generated =
            backend.generate(
                BackendGenerate(
                    payload.generationId,
                    payloadHash,
                    payload.logicalNameHash,
                    payload.challenge,
                    payload.keySpec,
                    wireCaller,
                )
            )
        return GenerateResultPayload(payload.generationId, generated.handle, generated.metadata)
    }

    private fun metadata(
        payload: GetMetadataRequestPayload,
        caller: WireCallerIdentity,
    ): GetMetadataResultPayload = GetMetadataResultPayload(backend.metadata(payload.handle, caller))

    private fun delete(
        payload: DeleteRequestPayload,
        payloadHash: ByteArray,
        wireCaller: WireCallerIdentity,
    ): DeleteResultPayload {
        backend.delete(BackendDelete(payload.deletionId, payloadHash, payload.handle, wireCaller))
        return DeleteResultPayload(payload.deletionId)
    }

    private fun begin(
        payload: BeginRequestPayload,
        payloadHash: ByteArray,
        wireCaller: WireCallerIdentity,
    ): BeginResultPayload =
        synchronized(operationMonitor) {
            if (payload.step != 0uL) fail(WireErrorCode.SEQUENCE_ERROR)
            operationsByClientId[payload.operationId]?.let { ledger ->
                ledger.requireCaller(wireCaller)
                val replay = ledger.replay(0uL, Method.BEGIN, payloadHash)
                val success = replay as? WireOutcome.Success ?: fail(WireErrorCode.INTERNAL_ERROR)
                return@synchronized success.payload as BeginResultPayload
            }

            val operation = backend.begin(payload.handle, payload.operationSpec, wireCaller)
            val result = BeginResultPayload(operation, 0uL)
            val ledger =
                OperationLedger(
                    payload.operationId,
                    wireCaller,
                    operation,
                    CachedOperationStep(Method.BEGIN, payloadHash, WireOutcome.Success(result)),
                )
            operationsByClientId[payload.operationId] = ledger
            operationsByDonorId[operation.id] = ledger
            result.defensiveCopy() as BeginResultPayload
        }

    private fun operationStep(
        payload: LifecycleRequestPayload,
        operation: WireOperationHandle,
        step: ULong,
        payloadHash: ByteArray,
        wireCaller: WireCallerIdentity,
    ): WireOutcome =
        synchronized(operationMonitor) {
            val ledger =
                operationsByDonorId[operation.id] ?: fail(WireErrorCode.INVALID_OPERATION_HANDLE)
            ledger.requireCaller(wireCaller)
            if (!ledger.matches(operation)) fail(WireErrorCode.INVALID_OPERATION_HANDLE)
            ledger.cached(step)?.let { cached ->
                return@synchronized cached.replay(payload.method, payloadHash)
            }
            if (ledger.terminal) fail(WireErrorCode.INVALID_STATE)
            if (step == ULong.MAX_VALUE || step != ledger.nextStep) {
                fail(WireErrorCode.SEQUENCE_ERROR)
            }

            val outcome =
                try {
                    when (payload) {
                        is UpdateAadRequestPayload -> {
                            backend.abort(operation, wireCaller)
                            ledger.terminal = true
                            WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD)
                        }
                        is UpdateRequestPayload ->
                            WireOutcome.Success(
                                UpdateResultPayload(
                                    step,
                                    backend.update(operation, payload.input, wireCaller),
                                )
                            )
                        is FinishRequestPayload -> {
                            val output = backend.finish(operation, payload.input, wireCaller)
                            ledger.terminal = true
                            WireOutcome.Success(FinishResultPayload(step, output))
                        }
                        is AbortRequestPayload -> {
                            backend.abort(operation, wireCaller)
                            ledger.terminal = true
                            WireOutcome.Success(AbortResultPayload(step))
                        }
                        else -> fail(WireErrorCode.INVALID_ARGUMENT)
                    }
                } catch (failure: WireBackendFailure) {
                    runCleanup { backend.abort(operation, wireCaller) }
                    ledger.terminal = true
                    WireOutcome.Error(failure.code)
                }
            ledger.cache(step, payload.method, payloadHash, outcome)
            ledger.nextStep = step + 1uL
            outcome.defensiveCopy()
        }

    private fun runCleanup(block: () -> Unit): CleanupResult =
        try {
            block()
            CleanupResult.COMPLETED
        } catch (_: RuntimeException) {
            CleanupResult.FAILED
        }

    private fun requestFingerprint(request: WireRequestEnvelope): ByteArray =
        canonicalBytes(
                "wire-donor-authenticated-request-v1".encodeToByteArray(),
                byteArrayOf(1),
                expectedSessionId,
                expectedClientNonce,
                expectedServerNonce,
                pair.targetPin.encodeToByteArray(),
                pair.donorPin.encodeToByteArray(),
                "target-to-donor".encodeToByteArray(),
                request.requestId.toBytes(),
                ByteBuffer.allocate(ULong.SIZE_BYTES).putLong(request.sequence.toLong()).array(),
                ByteBuffer.allocate(Int.SIZE_BYTES)
                    .putInt(methodFingerprintTag(request.method))
                    .array(),
                ByteBuffer.allocate(Long.SIZE_BYTES + Int.SIZE_BYTES)
                    .putLong(request.deadline.epochSecond)
                    .putInt(request.deadline.nano)
                    .array(),
                request.caller.signingCertificateDigest.encodeToByteArray(),
                request.caller.attestationApplicationIdDigest.encodeToByteArray(),
                request.payloadHash,
            )
            .sha256()

    private fun methodFingerprintTag(method: Method): Int =
        when (method) {
            Method.GENERATE -> 1
            Method.IMPORT -> 2
            Method.GET_METADATA -> 3
            Method.DELETE -> 4
            Method.BEGIN -> 5
            Method.UPDATE_AAD -> 6
            Method.UPDATE -> 7
            Method.FINISH -> 8
            Method.ABORT -> 9
        }

    private class OperationLedger(
        val clientOperationId: UUID,
        val caller: WireCallerIdentity,
        val operation: WireOperationHandle,
        begin: CachedOperationStep,
    ) {
        private val steps = mutableMapOf(0uL to begin)
        var nextStep = 1uL
        var terminal = false

        fun requireCaller(presented: WireCallerIdentity) {
            if (caller != presented) fail(WireErrorCode.WRONG_CALLER)
        }

        fun matches(presented: WireOperationHandle): Boolean =
            operation.id == presented.id &&
                operation.keyId == presented.keyId &&
                MessageDigest.isEqual(operation.binding, presented.binding)

        fun cached(step: ULong): CachedOperationStep? = steps[step]

        fun replay(step: ULong, method: Method, payloadHash: ByteArray): WireOutcome =
            steps.getValue(step).replay(method, payloadHash)

        fun cache(step: ULong, method: Method, payloadHash: ByteArray, outcome: WireOutcome) {
            steps[step] = CachedOperationStep(method, payloadHash, outcome)
        }
    }

    private class CachedOperationStep(
        private val method: Method,
        payloadHash: ByteArray,
        outcome: WireOutcome,
    ) {
        private val hashBytes = payloadHash.copyOf()
        private val storedOutcome = outcome.defensiveCopy()

        fun replay(method: Method, payloadHash: ByteArray): WireOutcome {
            if (this.method != method || !MessageDigest.isEqual(hashBytes, payloadHash)) {
                fail(WireErrorCode.REPLAY_CONFLICT)
            }
            return storedOutcome.defensiveCopy()
        }
    }

    private inner class CachedSessionResponse(
        fingerprint: ByteArray,
        response: WireResponseEnvelope,
    ) {
        private val fingerprintBytes = fingerprint.copyOf()
        private val storedResponse = response.defensiveCopy()

        fun matches(fingerprint: ByteArray): Boolean =
            MessageDigest.isEqual(fingerprintBytes, fingerprint)

        fun response(): WireResponseEnvelope = storedResponse.defensiveCopy()
    }

    private class DispatchFailure(val code: WireErrorCode) : RuntimeException()

    private enum class CleanupResult {
        COMPLETED,
        FAILED,
    }

    companion object {
        fun create(
            pair: PairIdentity,
            clientNonce: ByteArray,
            serverNonce: ByteArray,
            now: () -> Instant,
            backendFactory: (ByteArray) -> WireDonorBackend,
        ): WireDonorDispatcher {
            val sessionId = deriveSessionId(pair, clientNonce, serverNonce)
            val backend = backendFactory(sessionId.copyOf())
            return WireDonorDispatcher(pair, clientNonce, serverNonce, sessionId, now, backend)
        }

        private fun fail(code: WireErrorCode): Nothing = throw DispatchFailure(code)
    }
}

private fun UUID.toBytes(): ByteArray =
    ByteBuffer.allocate(16).putLong(mostSignificantBits).putLong(leastSignificantBits).array()
