package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CandidateBridgeStreamFramingTest {
    @Test
    fun request_frame_has_the_sidecars_bounded_outer_length() {
        val message =
            BridgeMessage.CandidateCommand(
                RequestId(7),
                CandidateBridgeOperation.GET,
                PublicBytes.of(byteArrayOf(1, 2, 3), BridgeLimits.MAX_FRAME_BYTES),
            )
        val canonical = BridgeCodec.encode(message, BridgeExchangeRole.CANDIDATE_REQUEST)
        val output = ByteArrayOutputStream()
        try {
            CandidateBridgeStreamFraming.write(output, canonical)
            val framed = output.toByteArray()
            assertEquals(canonical.size + Int.SIZE_BYTES, framed.size)
            assertEquals(canonical.size, java.nio.ByteBuffer.wrap(framed).int)
            assertArrayEquals(canonical, framed.copyOfRange(Int.SIZE_BYTES, framed.size))
        } finally {
            canonical.fill(0)
            message.close()
        }
    }

    @Test
    fun response_outer_length_is_consumed_before_canonical_decode() {
        val response =
            BridgeMessage.CandidateReply(
                RequestId(9),
                CandidateBridgeOperation.GET,
                PublicBytes.of(byteArrayOf(4, 5), BridgeLimits.MAX_FRAME_BYTES),
            )
        val canonical = BridgeCodec.encode(response, BridgeExchangeRole.CANDIDATE_RESPONSE)
        val framed = ByteArrayOutputStream()
        DataOutputStream(framed).use {
            it.writeInt(canonical.size)
            it.write(canonical)
        }
        try {
            val decoded =
                CandidateBridgeStreamFraming.decode(ByteArrayInputStream(framed.toByteArray()))
            assertTrue(decoded is BridgeResult.Success)
            val message = (decoded as BridgeResult.Success).value
            try {
                assertTrue(message is BridgeMessage.CandidateReply)
                message as BridgeMessage.CandidateReply
                assertEquals(response.requestId, message.requestId)
                assertEquals(response.operation, message.operation)
                assertArrayEquals(byteArrayOf(4, 5), message.payload.copyBytes())
            } finally {
                message.close()
            }
        } finally {
            canonical.fill(0)
            response.close()
        }
    }

    @Test
    fun invalid_outer_lengths_are_rejected_before_body_allocation() {
        val oversized = ByteArrayOutputStream()
        DataOutputStream(oversized).use { it.writeInt(BridgeLimits.MAX_FRAME_BYTES + 1) }
        val result =
            CandidateBridgeStreamFraming.decode(ByteArrayInputStream(oversized.toByteArray()))
        assertTrue(result is BridgeResult.Failure)
        assertEquals(BridgeError.FrameTooLarge, (result as BridgeResult.Failure).error)
    }
}
