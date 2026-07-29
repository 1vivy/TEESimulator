package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class WireDonorBackendReviewTest {
    private val pair = PairIdentity("target-pinned-cert", "donor-pinned-cert")
    private val caller = WireCallerIdentity("signer-sha256", "attestation-application-id")
    private val otherCaller = WireCallerIdentity("other-signer", "attestation-application-id")
    private val clientNonce = bytes(32, 1)
    private val serverNonce = bytes(32, 2)
    private val now = Instant.parse("2026-07-25T12:00:00Z")
    private val keySpec =
        WireKeySpec(WireKeyAlgorithm.EC, WireEcCurve.P256, WireDigest.SHA256, WireKeyPurpose.SIGN)
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)

    @Test
    fun sharedDonorStoreDoesNotShareSessionOperationOwnership() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, MutableClock(now), donorStore, counters)
        val owner = InMemoryWireDonorBackend(pair, root, wireStore)
        val otherSession = InMemoryWireDonorBackend(pair, root, wireStore)
        val generated = generate(owner, uuid(1))
        val updateOperation = owner.begin(generated.handle, operationSpec, caller)
        val finishOperation = owner.begin(generated.handle, operationSpec, caller)
        val abortOperation = owner.begin(generated.handle, operationSpec, caller)

        assertBackendFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            otherSession.update(updateOperation, bytes(4, 10), caller)
        }
        assertBackendFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            otherSession.finish(finishOperation, bytes(4, 11), caller)
        }
        assertBackendFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            otherSession.abort(abortOperation, caller)
        }
        assertBackendFailure(WireErrorCode.WRONG_CALLER) {
            owner.update(updateOperation, bytes(4, 12), otherCaller)
        }

        assertEquals(0, counters.update)
        assertEquals(0, counters.abort)
        listOf(updateOperation, finishOperation, abortOperation).forEach { operation ->
            assertEquals(OperationState.BEGUN, root.operationState(operation.toHost()))
        }
    }

    @Test
    fun terminalBackendErrorIsCachedAndAbortedOnlyOnce() {
        val backend =
            FailingBackend(
                updateFailure = WireBackendFailure(WireErrorCode.INVALID_STATE),
                abortFailure = WireBackendFailure(WireErrorCode.DONOR_UNAVAILABLE),
            )
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)
        val generated =
            success<GenerateResultPayload>(dispatcher, request(generatePayload(uuid(10)), 0uL))
        val begun =
            success<BeginResultPayload>(
                dispatcher,
                request(BeginRequestPayload(uuid(11), 0uL, generated.handle, operationSpec), 1uL),
            )
        val failedStep = UpdateRequestPayload(begun.operation, 1uL, bytes(4, 20))

        assertError(WireErrorCode.INVALID_STATE, dispatcher.dispatch(request(failedStep, 2uL)))
        assertError(WireErrorCode.INVALID_STATE, dispatcher.dispatch(request(failedStep, 3uL)))
        assertError(
            WireErrorCode.REPLAY_CONFLICT,
            dispatcher.dispatch(
                request(UpdateRequestPayload(begun.operation, 1uL, bytes(4, 21)), 4uL)
            ),
        )
        assertError(
            WireErrorCode.INVALID_STATE,
            dispatcher.dispatch(
                request(UpdateRequestPayload(begun.operation, 2uL, bytes(4, 22)), 5uL)
            ),
        )

        assertEquals(1, backend.updateCalls)
        assertEquals(1, backend.abortCalls)
    }

    @Test
    fun inMemoryTerminalFailureAbortsDonorBeforeEvictionAndReplaysOriginalError() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, MutableClock(now), donorStore, counters)
        val backend = InMemoryWireDonorBackend(pair, root, wireStore)
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)
        val generated =
            success<GenerateResultPayload>(dispatcher, request(generatePayload(uuid(12)), 0uL))
        val begun =
            success<BeginResultPayload>(
                dispatcher,
                request(BeginRequestPayload(uuid(13), 0uL, generated.handle, operationSpec), 1uL),
            )
        var operationCalls = 0
        wireStore.beforeOperationDonorCallForTest = {
            operationCalls++
            throw IllegalStateException("forced operation failure")
        }
        val failedStep = UpdateRequestPayload(begun.operation, 1uL, bytes(4, 23))

        assertError(WireErrorCode.INTERNAL_ERROR, dispatcher.dispatch(request(failedStep, 2uL)))
        assertEquals(OperationState.ABORTED, root.operationState(begun.operation.toHost()))
        assertEquals(0, counters.update)
        assertEquals(1, counters.abort)

        assertError(WireErrorCode.INTERNAL_ERROR, dispatcher.dispatch(request(failedStep, 3uL)))
        assertEquals(1, operationCalls)
        assertEquals(0, counters.update)
        assertEquals(1, counters.abort)

        dispatcher.close()
        assertEquals(1, counters.abort)
    }

    @Test
    fun inMemoryCloseAttemptsEveryOperationOnceWhenOneAbortFails() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, MutableClock(now), donorStore, counters)
        val backend = InMemoryWireDonorBackend(pair, root, wireStore)
        val generated = generate(backend, uuid(20))
        val first = backend.begin(generated.handle, operationSpec, caller)
        val second = backend.begin(generated.handle, operationSpec, caller)
        val attempts = mutableListOf<UUID>()
        wireStore.closeAbortForTest = { handle: OperationHandle, identity: CallerIdentity ->
            attempts += handle.id
            if (handle.id == first.id) {
                throw DonorException.InvalidState()
            }
            root.abort(handle, identity)
        }

        backend.close()
        backend.close()

        assertEquals(listOf(first.id, second.id), attempts)
        assertEquals(1, counters.abort)
        assertEquals(OperationState.BEGUN, root.operationState(first.toHost()))
        assertEquals(OperationState.ABORTED, root.operationState(second.toHost()))
    }

    @Test
    fun dispatcherCloseAttemptsBackendOnceAndNeverThrows() {
        val backend = FailingBackend(closeFailure = IllegalStateException("close failed"))
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)

        dispatcher.close()
        dispatcher.close()

        assertEquals(1, backend.closeCalls)
    }

    private inner class FailingBackend(
        private val updateFailure: WireBackendFailure? = null,
        private val abortFailure: WireBackendFailure? = null,
        private val closeFailure: RuntimeException? = null,
    ) : WireDonorBackend {
        private val handle = WireKeyHandle(uuid(100), bytes(32, 100))
        private val metadata =
            WireKeyMetadata(
                KeyState.ACTIVE,
                bytes(32, 101),
                bytes(32, 102),
                listOf(bytes(32, 103)),
                keySpec,
            )
        private val operation = WireOperationHandle(uuid(101), handle.id, bytes(32, 104))
        var updateCalls = 0
        var abortCalls = 0
        var closeCalls = 0

        override fun generate(command: BackendGenerate) = BackendGeneratedKey(handle, metadata)

        override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity) = metadata

        override fun delete(command: BackendDelete) = Unit

        override fun begin(
            handle: WireKeyHandle,
            spec: WireOperationSpec,
            caller: WireCallerIdentity,
        ) = operation

        override fun update(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray {
            updateCalls++
            updateFailure?.let { throw it }
            return ByteArray(0)
        }

        override fun finish(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ) = bytes(32, 105)

        override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) {
            abortCalls++
            abortFailure?.let { throw it }
        }

        override fun close() {
            closeCalls++
            closeFailure?.let { throw it }
        }
    }

    private fun generate(backend: InMemoryWireDonorBackend, id: UUID) =
        backend.generate(
            BackendGenerate(
                id,
                bytes(32, id.leastSignificantBits.toInt()),
                bytes(32, 40),
                bytes(32, 41),
                keySpec,
                caller,
            )
        )

    private fun generatePayload(id: UUID) =
        GenerateRequestPayload(id, bytes(32, 50), bytes(32, 51), keySpec)

    private fun request(payload: LifecycleRequestPayload, sequence: ULong) =
        WireRequestEnvelope(
            ProtocolVersion.V1,
            deriveSessionId(pair, clientNonce, serverNonce),
            clientNonce,
            serverNonce,
            sequence,
            UUID.randomUUID(),
            NormalizedWireCodec.payloadHash(payload),
            payload.method,
            now.plusSeconds(10),
            caller,
            payload,
        )

    private inline fun <reified T : LifecycleResultPayload> success(
        dispatcher: WireDonorDispatcher,
        request: WireRequestEnvelope,
    ): T = assertIs<T>(assertIs<WireOutcome.Success>(dispatcher.dispatch(request).outcome).payload)

    private fun assertError(code: WireErrorCode, response: WireResponseEnvelope) {
        assertEquals(code, assertIs<WireOutcome.Error>(response.outcome).code)
    }

    private fun assertBackendFailure(code: WireErrorCode, block: () -> Unit) {
        assertEquals(code, assertFailsWith<WireBackendFailure> { block() }.code)
    }

    private fun WireOperationHandle.toHost() = OperationHandle(id, keyId, binding)

    private fun uuid(value: Int) = UUID(0, value.toLong())

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it + seed).toByte() }
}
