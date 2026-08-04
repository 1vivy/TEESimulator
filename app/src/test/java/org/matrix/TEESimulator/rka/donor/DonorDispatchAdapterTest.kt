package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BridgeCodec
import org.matrix.TEESimulator.rka.bridge.BridgeDirection
import org.matrix.TEESimulator.rka.bridge.BridgeExchangeRole
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.BridgeTag
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.bridge.RequestId

class DonorDispatchAdapterTest {
    @Test
    fun productionAdapterDispatchesTypedCommandToDonorBackend() {
        // Given
        val fixture = DonorFixture()
        val backend = DonorKeyMintBackend(FakeDonorKeyMintDevice(fixture), fixture.journal)
        val command =
            BridgeMessage.CandidateCommand(
                RequestId(21),
                CandidateBridgeOperation.LIST,
                donorTestCandidate,
                PublicBytes.of(ByteArray(0), BridgeLimits.MAX_FRAME_BYTES - 5),
            )

        // When
        val response = DonorDispatchAdapter.dispatch(command, backend)

        // Then
        assertTrue(response is BridgeMessage.CandidateReply)
        val reply = response as BridgeMessage.CandidateReply
        assertEquals(CandidateBridgeOperation.LIST, reply.operation)
        assertEquals(0, reply.payload.copyBytes().single().toInt())
        response.close()
        command.close()
    }

    @Test
    fun dispatchRejectsACommandWhoseCandidateIdIsAbsent() {
        // Given
        val body =
            ByteArrayOutputStream().use { bytes ->
                DataOutputStream(bytes).use {
                    it.writeByte(CandidateBridgeOperation.LIST.wire)
                    it.writeInt(0)
                }
                bytes.toByteArray()
            }
        val legacyCommand =
            BridgeCodec.headerForTest(
                BridgeDirection.SIDECAR_TO_BROKER,
                BridgeTag.CANDIDATE_COMMAND,
                22,
                body.size.toLong(),
            ) + body

        // When
        val decoded =
            BridgeCodec.decode(
                ByteArrayInputStream(legacyCommand),
                BridgeExchangeRole.DONOR_REQUEST,
            )

        // Then
        try {
            assertTrue(decoded is BridgeResult.Failure)
        } finally {
            if (decoded is BridgeResult.Success) decoded.value.close()
            legacyCommand.fill(0)
            body.fill(0)
        }
    }

    @Test
    fun candidateCommandRoundTripsTheCandidateIdAtFixedOffset() {
        // Given
        val candidateId = ByteArray(32) { 0x44 }
        val body =
            ByteArrayOutputStream().use { bytes ->
                DataOutputStream(bytes).use {
                    it.writeByte(CandidateBridgeOperation.LIST.wire)
                    it.write(candidateId)
                    it.writeInt(0)
                }
                bytes.toByteArray()
            }
        val command =
            BridgeCodec.headerForTest(
                BridgeDirection.SIDECAR_TO_BROKER,
                BridgeTag.CANDIDATE_COMMAND,
                23,
                body.size.toLong(),
            ) + body

        // When
        val decoded =
            BridgeCodec.decode(
                ByteArrayInputStream(command),
                BridgeExchangeRole.DONOR_REQUEST,
            )
        val roundTripped =
            if (decoded is BridgeResult.Success) {
                BridgeCodec.encode(decoded.value, BridgeExchangeRole.DONOR_REQUEST)
            } else {
                ByteArray(0)
            }

        // Then
        try {
            assertArrayEquals(candidateId, command.copyOfRange(25, 57))
            assertTrue(decoded is BridgeResult.Success)
            assertArrayEquals(command, roundTripped)
        } finally {
            if (decoded is BridgeResult.Success) decoded.value.close()
            roundTripped.fill(0)
            command.fill(0)
            body.fill(0)
            candidateId.fill(0)
        }
    }
}
