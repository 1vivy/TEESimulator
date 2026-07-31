package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
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
            QuarantineResult.ALREADY_QUARANTINED,
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
}
