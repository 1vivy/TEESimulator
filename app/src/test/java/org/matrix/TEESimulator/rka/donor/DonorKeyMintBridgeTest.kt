package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BridgeCodec
import org.matrix.TEESimulator.rka.bridge.BridgeExchangeRole
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.bridge.RequestId

class DonorKeyMintBridgeTest {
    @Test
    fun authenticatedDonorDispatcherSupportsEveryLifecycleCommand() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture)
        val backend = DonorKeyMintBackend(device, fixture.journal)

        // When
        val generated =
            dispatch(
                backend,
                CandidateBridgeOperation.GENERATE,
                DonorBridgeCodec.generateCommand(fixture.request()),
            )
        dispatch(backend, CandidateBridgeOperation.GET, DonorBridgeCodec.keyCommand(fixture.alias))
        val listed = dispatch(backend, CandidateBridgeOperation.LIST, ByteArray(0))
        val begun =
            dispatch(
                backend,
                CandidateBridgeOperation.BEGIN,
                DonorBridgeCodec.keyCommand(fixture.alias),
            )
        val operation = DonorOperationHandle.of(begun)
        dispatch(
            backend,
            CandidateBridgeOperation.UPDATE_AAD,
            DonorBridgeCodec.operationCommand(operation, byteArrayOf(1)),
        )
        dispatch(
            backend,
            CandidateBridgeOperation.UPDATE,
            DonorBridgeCodec.operationCommand(operation, "bridge".toByteArray()),
        )
        val signature =
            dispatch(
                backend,
                CandidateBridgeOperation.FINISH,
                DonorBridgeCodec.operationCommand(operation, ByteArray(0)),
            )
        val abortHandle =
            DonorOperationHandle.of(
                dispatch(
                    backend,
                    CandidateBridgeOperation.BEGIN,
                    DonorBridgeCodec.keyCommand(fixture.alias),
                )
            )
        dispatch(
            backend,
            CandidateBridgeOperation.ABORT,
            DonorBridgeCodec.operationCommand(abortHandle, ByteArray(0)),
        )
        dispatch(
            backend,
            CandidateBridgeOperation.DELETE,
            DonorBridgeCodec.keyCommand(fixture.alias),
        )

        // Then
        assertTrue(generated.isNotEmpty())
        assertTrue(!generated.contains(ByteArray(32) { 0x5a }))
        assertTrue(!generated.contains(ByteArray(32) { 0x6b }))
        assertEquals(1, listed[0].toInt())
        assertTrue(readBounded(signature).isNotEmpty())
        assertEquals(0, backend.list().size)
    }

    @Test
    fun donorRequestAndResponseRolesAdmitTypedLifecycleFrames() {
        // Given
        val fixture = DonorFixture()
        val command =
            BridgeMessage.CandidateCommand(
                RequestId(20),
                CandidateBridgeOperation.GENERATE,
                PublicBytes.of(
                    DonorBridgeCodec.generateCommand(fixture.request()),
                    BridgeLimits.MAX_FRAME_BYTES - 5,
                ),
            )

        // When
        val requestBytes = BridgeCodec.encode(command, BridgeExchangeRole.DONOR_REQUEST)
        val decoded =
            BridgeCodec.decode(ByteArrayInputStream(requestBytes), BridgeExchangeRole.DONOR_REQUEST)
        val reply =
            BridgeMessage.CandidateReply(
                RequestId(20),
                CandidateBridgeOperation.GENERATE,
                PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES - 5),
            )
        val responseBytes = BridgeCodec.encode(reply, BridgeExchangeRole.DONOR_RESPONSE)
        val decodedResponse =
            BridgeCodec.decode(
                ByteArrayInputStream(responseBytes),
                BridgeExchangeRole.DONOR_RESPONSE,
            )

        // Then
        assertTrue(decoded is BridgeResult.Success)
        assertTrue(decodedResponse is BridgeResult.Success)
        (decoded as BridgeResult.Success).value.close()
        (decodedResponse as BridgeResult.Success).value.close()
        reply.close()
        command.close()
    }

    @Test
    fun ambiguousGenerationReturnsOnlyErrorAndNeverRetries() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture).apply { failGenerate = true }
        val backend = DonorKeyMintBackend(device, fixture.journal)

        // When
        val first = dispatchMessage(backend, fixture)
        val second = dispatchMessage(backend, fixture)

        // Then
        assertTrue(first is BridgeMessage.Error)
        assertTrue(second is BridgeMessage.Error)
        assertEquals(1, device.generateCalls)
        first.close()
        second.close()
    }

    private fun dispatch(
        backend: DonorKeyMintBackend,
        operation: CandidateBridgeOperation,
        payload: ByteArray,
    ): ByteArray {
        val command =
            BridgeMessage.CandidateCommand(
                RequestId(operation.wire.toLong()),
                operation,
                PublicBytes.of(payload, BridgeLimits.MAX_FRAME_BYTES - 5),
            )
        return try {
            val response = DonorBridgeDispatcher.dispatch(command, backend)
            try {
                require(response is BridgeMessage.CandidateReply) { response.toString() }
                response.payload.copyBytes()
            } finally {
                response.close()
            }
        } finally {
            command.close()
            payload.fill(0)
        }
    }

    private fun dispatchMessage(
        backend: DonorKeyMintBackend,
        fixture: DonorFixture,
    ): BridgeMessage {
        val payload = DonorBridgeCodec.generateCommand(fixture.request())
        val command =
            BridgeMessage.CandidateCommand(
                RequestId(91),
                CandidateBridgeOperation.GENERATE,
                PublicBytes.of(payload, BridgeLimits.MAX_FRAME_BYTES - 5),
            )
        payload.fill(0)
        return try {
            DonorBridgeDispatcher.dispatch(command, backend)
        } finally {
            command.close()
        }
    }

    private fun readBounded(value: ByteArray): ByteArray =
        DataInputStream(ByteArrayInputStream(value)).use {
            ByteArray(it.readInt()).also(it::readFully)
        }

    private fun ByteArray.contains(candidate: ByteArray): Boolean =
        indices.any { start ->
            start + candidate.size <= size &&
                candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
        }
}
