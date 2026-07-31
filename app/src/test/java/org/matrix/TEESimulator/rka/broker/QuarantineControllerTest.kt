package org.matrix.TEESimulator.rka.broker

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BrokerBatchId
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.RequestId

class QuarantineControllerTest {
    @Test
    fun authenticatedRequestCancelsDiscardsAndWipesEachHandleExactlyOnce() {
        val events = mutableListOf<Pair<String, ByteArray>>()
        val handles = listOf(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val controller =
            QuarantineController(
                exactQuarantine = { supplied ->
                    supplied.zip(handles).all { (actual, expected) ->
                        actual.contentEquals(expected)
                    }
                },
                cancel = { events += "cancel" to ByteArray(0) },
                discard = { events += "discard" to it.copyOf() },
                wipe = { events += "wipe" to it.copyOf() },
            )

        val result =
            controller.quarantine(
                AuthenticatedQuarantineRequest.fromTrustedBridge(RequestId(7), handles)
            )

        assertEquals(QuarantineResult.QUARANTINED, result)
        assertEquals(1, events.count { it.first == "cancel" })
        assertEquals(2, events.count { it.first == "discard" })
        assertEquals(2, events.count { it.first == "wipe" })
        assertFalse(controller.activationAllowed(RequestId(7)))
        assertTrue(controller.activationAllowed(RequestId(8)))
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller.quarantine(
                AuthenticatedQuarantineRequest.fromTrustedBridge(RequestId(7), handles)
            ),
        )
    }

    @Test
    fun mismatchedHandleSetFailsClosedBeforeReuse() {
        val controller =
            QuarantineController(exactQuarantine = { false }, cancel = {}, discard = {}, wipe = {})
        val result =
            controller.quarantine(
                AuthenticatedQuarantineRequest.fromTrustedBridge(
                    RequestId(9),
                    listOf(ByteArray(32) { 9 }),
                )
            )
        assertEquals(QuarantineResult.HANDLE_MISMATCH, result)
        assertTrue(controller.quarantineRetained())
        assertFalse(controller.activationAllowed(RequestId(9)))
    }

    @Test
    fun durableReceiptSurvivesControllerRestartAndTamperingIsRejected() {
        val handle = ByteArray(32) { 4 }
        val batch = ByteArray(16) { 5 }
        var effects = 0
        var durable: ByteArray? = null
        val receipts =
            object : QuarantineReceiptStore {
                override fun read(): ByteArray? = durable?.copyOf()

                override fun replace(receipt: ByteArray) {
                    durable = receipt.copyOf()
                }
            }
        fun controller() =
            QuarantineController(
                exactQuarantine = { true },
                cancel = { effects++ },
                discard = { effects++ },
                wipe = { effects++ },
                receipts = receipts,
                expectedBatch = { batch.copyOf() },
            )

        assertEquals(
            QuarantineResult.QUARANTINED,
            controller().quarantine(request(11, batch, handle)),
        )
        assertEquals(3, effects)
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller().quarantine(request(11, batch, handle)),
        )
        assertEquals(3, effects)
        assertEquals(
            QuarantineResult.HANDLE_MISMATCH,
            controller().quarantine(request(11, ByteArray(16) { 6 }, handle)),
        )

        val actionIds = actionIds(11, batch, listOf(handle))
        actionIds.first()[0] = (actionIds.first()[0].toInt() xor 1).toByte()
        val batchId = BrokerBatchId.of(batch)
        val hashes = actionIds.map(Hash32::of)
        try {
            assertThrows(IllegalArgumentException::class.java) {
                AuthenticatedQuarantineRequest.fromTrustedBridge(
                    RequestId(11),
                    listOf(handle),
                    batchId,
                    hashes,
                )
            }
        } finally {
            batchId.close()
            hashes.forEach(Hash32::close)
        }
    }

    private fun request(
        requestId: Long,
        batch: ByteArray,
        handle: ByteArray,
    ): AuthenticatedQuarantineRequest {
        val batchId = BrokerBatchId.of(batch)
        val ids = actionIds(requestId, batch, listOf(handle)).map(Hash32::of)
        return try {
            AuthenticatedQuarantineRequest.fromTrustedBridge(
                RequestId(requestId),
                listOf(handle),
                batchId,
                ids,
            )
        } finally {
            batchId.close()
            ids.forEach(Hash32::close)
        }
    }

    private fun actionIds(
        requestId: Long,
        batch: ByteArray,
        handles: List<ByteArray>,
    ): List<ByteArray> {
        fun derive(tag: Int, handle: ByteArray?): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("TEESimulator-RS quarantine action v1\u0000".toByteArray())
            digest.update(
                ByteBuffer.allocate(Long.SIZE_BYTES)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putLong(requestId)
                    .array()
            )
            digest.update(batch)
            digest.update(tag.toByte())
            handle?.let(digest::update)
            return digest.digest()
        }
        return buildList {
            add(derive(0, null))
            handles.forEach {
                add(derive(1, it))
                add(derive(2, it))
            }
        }
    }
}
