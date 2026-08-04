package org.matrix.TEESimulator.rka.candidate

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BridgeCodec
import org.matrix.TEESimulator.rka.bridge.BridgeExchangeRole
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.PublicBytes

class BridgeRemoteCandidateBackendTest {
    @Test
    fun productionBackendExchangesEveryRemoteOperationSuccessfully() {
        val key = RemoteKeyHandle.of(ByteArray(16) { 1 })
        val operation = RemoteOperationHandle.of(ByteArray(16) { 2 })
        val identity = IdentityHash.of(ByteArray(32) { 3 })
        val seen = mutableListOf<CandidateBridgeOperation>()
        val frames = mutableListOf<ByteArray>()
        val backend = BridgeRemoteCandidateBackend(identity) { request ->
            val command = request as BridgeMessage.CandidateCommand
            seen += command.operation
            frames += BridgeCodec.encode(command, BridgeExchangeRole.CANDIDATE_REQUEST)
            val payload =
                when (command.operation) {
                    CandidateBridgeOperation.GENERATE ->
                        CandidateBridgePayloadCodec.generateReply(
                            RemoteKeyMaterial(
                                key,
                                7,
                                8,
                                listOf(byteArrayOf(1), byteArrayOf(2)),
                                CandidateCharacteristics.foreground(),
                            )
                        )
                    CandidateBridgeOperation.LIST ->
                        CandidateBridgePayloadCodec.handlesReply(listOf(key))
                    CandidateBridgeOperation.BEGIN ->
                        CandidateBridgePayloadCodec.operationReply(operation)
                    CandidateBridgeOperation.FINISH ->
                        CandidateBridgePayloadCodec.outputReply(byteArrayOf(9, 8))
                    else -> ByteArray(0)
                }
            request.close()
            BridgeResult.Success(
                BridgeMessage.CandidateReply(
                    command.requestId,
                    command.operation,
                    PublicBytes.of(payload, BridgeLimits.MAX_FRAME_BYTES - 5),
                )
            )
        }
        assertTrue(
            backend.generate(RemoteGenerateCommand(key, identity, byteArrayOf(4)))
                is CandidateResult.Success
        )
        assertTrue(backend.get(key) is CandidateResult.Success)
        assertEquals(listOf(key), (backend.list(identity) as CandidateResult.Success).value)
        assertTrue(backend.delete(key) is CandidateResult.Success)
        assertEquals(operation, (backend.begin(key) as CandidateResult.Success).value)
        assertTrue(backend.updateAad(operation, byteArrayOf(5)) is CandidateResult.Success)
        assertTrue(backend.update(operation, byteArrayOf(6)) is CandidateResult.Success)
        assertArrayEquals(
            byteArrayOf(9, 8),
            (backend.finish(operation, byteArrayOf(7)) as CandidateResult.Success).value,
        )
        assertTrue(backend.abort(operation) is CandidateResult.Success)

        assertEquals(CandidateBridgeOperation.entries, seen)
        val forbidden = "private-key-material".toByteArray()
        assertFalse(
            frames.any { it.asList().windowed(forbidden.size).any { w -> w == forbidden.asList() } }
        )
    }

    @Test
    fun candidateCommandCodecIsCanonicalBoundedAndCorrelated() {
        val identity = IdentityHash.of(ByteArray(32) { 3 })
        CandidateBridgeOperation.entries.forEach { operation ->
            val message =
                BridgeMessage.CandidateCommand(
                    org.matrix.TEESimulator.rka.bridge.RequestId(operation.wire.toLong()),
                    operation,
                    identity,
                    PublicBytes.of(byteArrayOf(operation.wire.toByte()), 1),
                )
            val encoded = BridgeCodec.encode(message, BridgeExchangeRole.CANDIDATE_REQUEST)
            val decoded =
                BridgeCodec.decode(
                    ByteArrayInputStream(encoded),
                    BridgeExchangeRole.CANDIDATE_REQUEST,
                ) as BridgeResult.Success
            val command = decoded.value as BridgeMessage.CandidateCommand
            assertEquals(operation, command.operation)
            assertArrayEquals(byteArrayOf(operation.wire.toByte()), command.payload.copyBytes())
            command.close()
            message.close()
        }
        val tooLarge = ByteArray(BridgeLimits.MAX_FRAME_BYTES - 4)
        val rejected = runCatching {
            BridgeMessage.CandidateCommand(
                org.matrix.TEESimulator.rka.bridge.RequestId(1),
                CandidateBridgeOperation.UPDATE,
                identity,
                PublicBytes.of(tooLarge, BridgeLimits.MAX_FRAME_BYTES),
            )
        }
        assertTrue(rejected.isFailure)
    }
}
