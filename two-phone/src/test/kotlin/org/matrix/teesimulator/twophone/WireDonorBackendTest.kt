package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

class WireDonorBackendTest {
    private val pair = PairIdentity("target-pinned-cert", "donor-pinned-cert")
    private val clientNonce = bytes(32, 1)
    private val serverNonce = bytes(32, 2)
    private val caller = WireCallerIdentity("signer-sha256", "attestation-application-id")
    private val now = Instant.parse("2026-07-25T12:00:00Z")
    private val keySpec =
        WireKeySpec(WireKeyAlgorithm.EC, WireEcCurve.P256, WireDigest.SHA256, WireKeyPurpose.SIGN)
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)

    @Test
    fun dispatcherDelegatesLifecycleWorkToBackendWithoutEnvelopeState() {
        val backend = RecordingBackend()
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)
        val generate = GenerateRequestPayload(uuid(1), bytes(32, 10), bytes(32, 11), keySpec)

        val generated = success<GenerateResultPayload>(dispatcher, request(generate, 0uL))
        success<GetMetadataResultPayload>(
            dispatcher,
            request(GetMetadataRequestPayload(generated.handle), 1uL),
        )
        val begun =
            success<BeginResultPayload>(
                dispatcher,
                request(BeginRequestPayload(uuid(2), 0uL, generated.handle, operationSpec), 2uL),
            )
        val updateInput = bytes(8, 12)
        success<UpdateResultPayload>(
            dispatcher,
            request(UpdateRequestPayload(begun.operation, 1uL, updateInput), 3uL),
        )
        val finishInput = bytes(8, 13)
        success<FinishResultPayload>(
            dispatcher,
            request(FinishRequestPayload(begun.operation, 2uL, finishInput), 4uL),
        )
        val aborting =
            success<BeginResultPayload>(
                dispatcher,
                request(BeginRequestPayload(uuid(3), 0uL, generated.handle, operationSpec), 5uL),
            )
        success<AbortResultPayload>(
            dispatcher,
            request(AbortRequestPayload(aborting.operation, 1uL), 6uL),
        )
        val delete = DeleteRequestPayload(uuid(4), generated.handle)
        success<DeleteResultPayload>(dispatcher, request(delete, 7uL))

        assertEquals(1, backend.generates.size)
        val command = backend.generates.single()
        assertEquals(generate.generationId, command.generationId)
        assertContentEquals(NormalizedWireCodec.payloadHash(generate), command.payloadHash)
        assertContentEquals(generate.logicalNameHash, command.logicalNameHash)
        assertContentEquals(generate.challenge, command.challenge)
        assertEquals(keySpec, command.keySpec)
        assertEquals(caller, command.caller)
        assertEquals(listOf(generated.handle.id), backend.metadataHandles.map { it.id })
        assertEquals(listOf(operationSpec, operationSpec), backend.beginSpecs)
        assertContentEquals(updateInput, backend.updateInputs.single())
        assertContentEquals(finishInput, backend.finishInputs.single())
        assertEquals(listOf(aborting.operation.id), backend.aborted.map { it.id })
        assertEquals(1, backend.deletes.size)
        assertEquals(delete.deletionId, backend.deletes.single().deletionId)
        assertContentEquals(
            NormalizedWireCodec.payloadHash(delete),
            backend.deletes.single().payloadHash,
        )
    }

    @Test
    fun backendCommandsAndGeneratedKeysDefensivelyCopyByteArrays() {
        val payloadHash = bytes(32, 20)
        val logicalNameHash = bytes(32, 21)
        val challenge = bytes(32, 22)
        val binding = bytes(32, 23)
        val generate =
            BackendGenerate(uuid(10), payloadHash, logicalNameHash, challenge, keySpec, caller)
        val handle = WireKeyHandle(uuid(11), binding)
        val delete = BackendDelete(uuid(12), payloadHash, handle, caller)
        val metadata =
            WireKeyMetadata(
                KeyState.ACTIVE,
                challenge,
                bytes(32, 24),
                listOf(bytes(32, 25)),
                keySpec,
            )
        val generated = BackendGeneratedKey(handle, metadata)

        payloadHash.fill(0)
        logicalNameHash.fill(0)
        challenge.fill(0)
        binding.fill(0)
        generate.payloadHash.fill(0)
        generate.logicalNameHash.fill(0)
        generate.challenge.fill(0)
        delete.payloadHash.fill(0)
        delete.handle.binding.fill(0)
        generated.handle.binding.fill(0)
        generated.metadata.publicKey.fill(0)

        assertContentEquals(bytes(32, 20), generate.payloadHash)
        assertContentEquals(bytes(32, 21), generate.logicalNameHash)
        assertContentEquals(bytes(32, 22), generate.challenge)
        assertContentEquals(bytes(32, 20), delete.payloadHash)
        assertContentEquals(bytes(32, 23), delete.handle.binding)
        assertContentEquals(bytes(32, 23), generated.handle.binding)
        assertContentEquals(bytes(32, 24), generated.metadata.publicKey)
    }

    @Test
    fun dispatcherMapsTypedBackendFailureAndPreservesItsCause() {
        val cause = IllegalStateException("backend detail")
        val failure = WireBackendFailure(WireErrorCode.DONOR_UNAVAILABLE, cause)
        val backend = RecordingBackend(generateFailure = failure)
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)

        val response = dispatcher.dispatch(request(generatePayload(uuid(20)), 0uL))

        assertEquals(
            WireErrorCode.DONOR_UNAVAILABLE,
            assertIs<WireOutcome.Error>(response.outcome).code,
        )
        assertSame(cause, failure.cause)
    }

    @Test
    fun dispatcherCloseIsIdempotentAndDelegatesBackendCleanupOnce() {
        val backend = RecordingBackend()
        val dispatcher = WireDonorDispatcher(pair, clientNonce, serverNonce, { now }, backend)
        val generated =
            success<GenerateResultPayload>(dispatcher, request(generatePayload(uuid(30)), 0uL))
        success<BeginResultPayload>(
            dispatcher,
            request(BeginRequestPayload(uuid(31), 0uL, generated.handle, operationSpec), 1uL),
        )

        dispatcher.close()
        dispatcher.close()

        assertEquals(1, backend.closeCalls)
    }

    @Test
    fun inMemoryBackendCloseBestEffortAbortsOnlyItsOpenOperations() {
        val clock = MutableClock(now)
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, clock, counters = counters)
        val backend = InMemoryWireDonorBackend(pair, root, InMemoryWireDonorStore())
        val generated =
            backend.generate(
                BackendGenerate(
                    uuid(40),
                    bytes(32, 40),
                    bytes(32, 41),
                    bytes(32, 42),
                    keySpec,
                    caller,
                )
            )
        val operation = backend.begin(generated.handle, operationSpec, caller)

        backend.close()
        backend.close()

        assertEquals(1, counters.abort)
        assertEquals(
            OperationState.ABORTED,
            root.operationState(OperationHandle(operation.id, operation.keyId, operation.binding)),
        )
    }

    private inner class RecordingBackend(private val generateFailure: WireBackendFailure? = null) :
        WireDonorBackend {
        val generates = mutableListOf<BackendGenerate>()
        val metadataHandles = mutableListOf<WireKeyHandle>()
        val deletes = mutableListOf<BackendDelete>()
        val beginSpecs = mutableListOf<WireOperationSpec>()
        val updateInputs = mutableListOf<ByteArray>()
        val finishInputs = mutableListOf<ByteArray>()
        val aborted = mutableListOf<WireOperationHandle>()
        var closeCalls = 0
        private var operationNumber = 0
        private val handle = WireKeyHandle(uuid(100), bytes(32, 100))
        private val metadata =
            WireKeyMetadata(
                KeyState.ACTIVE,
                bytes(32, 101),
                bytes(32, 102),
                listOf(bytes(32, 103)),
                keySpec,
            )

        override fun generate(command: BackendGenerate): BackendGeneratedKey {
            generateFailure?.let { throw it }
            generates += command
            return BackendGeneratedKey(handle, metadata)
        }

        override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata {
            metadataHandles += handle
            return metadata
        }

        override fun delete(command: BackendDelete) {
            deletes += command
        }

        override fun begin(
            handle: WireKeyHandle,
            spec: WireOperationSpec,
            caller: WireCallerIdentity,
        ): WireOperationHandle {
            beginSpecs += spec
            operationNumber++
            return WireOperationHandle(uuid(100 + operationNumber), handle.id, bytes(32, 110))
        }

        override fun update(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray {
            updateInputs += input.copyOf()
            return bytes(2, 120)
        }

        override fun finish(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray {
            finishInputs += input.copyOf()
            return bytes(32, 121)
        }

        override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) {
            aborted += operation
        }

        override fun close() {
            closeCalls++
        }
    }

    private fun generatePayload(id: UUID) =
        GenerateRequestPayload(id, bytes(32, 10), bytes(32, 11), keySpec)

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

    private fun uuid(value: Int) = UUID(0, value.toLong())

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it + seed).toByte() }
}
