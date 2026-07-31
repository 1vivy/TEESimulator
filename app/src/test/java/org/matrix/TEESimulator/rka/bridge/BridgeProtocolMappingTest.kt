package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeProtocolMappingTest {
    @Test
    fun every_request_has_one_response_tag_and_error_is_the_only_alternative() {
        val pairs =
            listOf(
                publicKeyRequest(1) to publicKeyResponse(1),
                updateRequest(2) to publicResult(2),
                BridgeMessage.Cancel(RequestId(3)) to BridgeMessage.Cancel(RequestId(3)),
            )
        for ((request, response) in pairs) {
            val correlation = BridgeProtocol.correlationFor(request, 9)
            assertTrue(correlation.accepts(response))
            assertTrue(
                correlation.accepts(
                    BridgeMessage.Error(
                        request.requestId,
                        BridgeErrorCode.INVALID_REQUEST,
                        Hash32.of(ByteArray(32)),
                    )
                )
            )
            val wrong =
                pairs.map(Pair<BridgeMessage, BridgeMessage>::second).first {
                    BridgeProtocol.tagOf(it) != BridgeProtocol.tagOf(response) &&
                        it.requestId != request.requestId
                }
            assertFalse(correlation.accepts(wrong))
            request.close()
            response.close()
        }
    }

    @Test
    fun role_direction_allowlists_reject_every_known_wrong_tag_before_body_decode() {
        val requestFrames = listOf(publicKeyRequest(11), updateRequest(12))
        val responseFrames =
            listOf(
                publicKeyResponse(11),
                publicResult(12),
                BridgeMessage.Error(
                    RequestId(14),
                    BridgeErrorCode.TRANSPORT,
                    Hash32.of(ByteArray(32)),
                ),
            )
        for (message in requestFrames) {
            val bytes = BridgeCodec.encode(message, BridgeExchangeRole.DONOR_REQUEST)
            assertTrue(
                BridgeCodec.decode(
                    ByteArrayInputStream(bytes),
                    BridgeExchangeRole.CANDIDATE_RESPONSE,
                ) is BridgeResult.Failure
            )
            bytes.fill(0)
            message.close()
        }
        for (message in responseFrames) {
            val bytes = BridgeCodec.encode(message, BridgeExchangeRole.CANDIDATE_RESPONSE)
            assertEquals(
                BridgeError.UnexpectedTag,
                (BridgeCodec.decode(ByteArrayInputStream(bytes), BridgeExchangeRole.DONOR_REQUEST)
                        as BridgeResult.Failure)
                    .error,
            )
            bytes.fill(0)
            message.close()
        }
    }

    @Test
    fun task8_golden_remains_the_exact_donor_request_mapping() {
        val request =
            BridgeMessage.PublicKeyRequest(
                RequestId(0x0102030405060708L),
                PublicBytes.of(ByteArray(16) { it.toByte() }, 64),
                2,
            )
        val encoded = BridgeCodec.encode(request, BridgeExchangeRole.DONOR_REQUEST)

        assertTrue(encoded.contentEquals(BRIDGE_GOLDEN_PUBLIC_KEY_REQUEST))
        assertTrue(
            BridgeCodec.decode(ByteArrayInputStream(encoded), BridgeExchangeRole.DONOR_REQUEST)
                is BridgeResult.Success
        )
        encoded.fill(0)
        request.close()
    }

    private fun publicKeyRequest(id: Long) =
        BridgeMessage.PublicKeyRequest(RequestId(id), PublicBytes.of(ByteArray(16), 64), 1)

    private fun publicKeyResponse(id: Long) =
        BridgeMessage.PublicKeyResponse(
            RequestId(id),
            PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
            testBatchId(),
            testKeyMetadata(Hash32.of(ByteArray(32))),
        )

    private fun updateRequest(id: Long) =
        BridgeMessage.UpdateRequest(
            RequestId(id),
            NetworkHandle.of(ByteArray(16)),
            PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_UPDATE_BYTES),
            1,
        )

    private fun publicResult(id: Long) =
        BridgeMessage.PublicResult(
            RequestId(id),
            NetworkHandle.of(ByteArray(16)),
            PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_CERTIFICATE_BYTES),
            listOf(PublicBytes.of(byteArrayOf(2), BridgeLimits.MAX_CERTIFICATE_BYTES)),
        )
}
