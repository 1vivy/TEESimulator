package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class DonorRuntimeOwnerStopFailureTest {
    @Test
    fun failedServerCloseRetainsServerAndEntersStopFailed() {
        val rig = DonorRuntimeTestRig()
        rig.owner.start("approved.profile", Instant.now())
        val server = rig.serverFactory.servers.single()
        val closeFailure = TestRuntimeFailure()
        server.closeOutcomes += DonorServerCloseOutcome.Incomplete(closeFailure)

        val failure =
            assertFailsWith<DonorRuntimeException.Unavailable> { rig.owner.stopUntil(123_456_789L) }

        assertSame(closeFailure, failure.cause)
        assertEquals(DonorRuntimeState.STOP_FAILED, rig.owner.state)
        assertEquals(1, server.closeCalls.get())
        assertEquals(listOf(123_456_789L), server.closeDeadlines.toList())
        assertEquals(1, rig.serverFactory.servers.size)
    }

    @Test
    fun secondStopRetriesSameServerAndReachesStopped() {
        val rig = DonorRuntimeTestRig()
        rig.owner.start("approved.profile", Instant.now())
        val server = rig.serverFactory.servers.single()
        server.closeOutcomes += DonorServerCloseOutcome.Incomplete(TestRuntimeFailure())
        server.closeOutcomes += DonorServerCloseOutcome.Closed
        assertFailsWith<DonorRuntimeException.Unavailable> { rig.owner.stopUntil(100L) }

        assertEquals(DonorRuntimeStopResult.STOPPED, rig.owner.stopUntil(200L))

        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
        assertEquals(2, server.closeCalls.get())
        assertEquals(listOf(100L, 200L), server.closeDeadlines.toList())
        assertEquals(1, rig.serverFactory.servers.size)
    }

    @Test
    fun startIsRejectedWhileStopFailed() {
        val rig = DonorRuntimeTestRig()
        rig.owner.start("approved.profile", Instant.now())
        val server = rig.serverFactory.servers.single()
        server.closeOutcomes += DonorServerCloseOutcome.Incomplete(TestRuntimeFailure())
        assertFailsWith<DonorRuntimeException.Unavailable> { rig.owner.stopUntil(100L) }
        val createCalls = rig.serverFactory.createCalls.get()

        assertFailsWith<DonorRuntimeException.Unavailable> {
            rig.owner.start("approved.profile", Instant.now())
        }

        assertEquals(DonorRuntimeState.STOP_FAILED, rig.owner.state)
        assertEquals(createCalls, rig.serverFactory.createCalls.get())
        assertEquals(1, server.closeCalls.get())
    }

    @Test
    fun failedStartWithIncompleteCandidateCleanupRemainsRetryable() {
        val rig = DonorRuntimeTestRig()
        val startFailure = TestRuntimeFailure()
        val cleanupFailure = TestRuntimeFailure()
        rig.serverFactory.nextStartFailure = startFailure
        rig.serverFactory.nextCloseOutcomes =
            listOf(
                DonorServerCloseOutcome.Incomplete(cleanupFailure),
                DonorServerCloseOutcome.Closed,
            )

        val failure =
            assertFailsWith<DonorRuntimeException.Unavailable> {
                rig.owner.start("approved.profile", Instant.now())
            }
        val server = rig.serverFactory.servers.single()

        assertSame(startFailure, failure.cause)
        assertSame(cleanupFailure, startFailure.suppressed.single())
        assertEquals(DonorRuntimeState.STOP_FAILED, rig.owner.state)
        assertEquals(1, server.closeCalls.get())
        assertEquals(DonorRuntimeStopResult.STOPPED, rig.owner.stopUntil(300L))
        assertEquals(2, server.closeCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
    }

    @Test
    fun failedStartWithSuccessfulCandidateCleanupIsConfirmedStopped() {
        val rig = DonorRuntimeTestRig()
        rig.serverFactory.nextStartFailure = TestRuntimeFailure()
        rig.serverFactory.nextCloseOutcomes = listOf(DonorServerCloseOutcome.Closed)

        assertFailsWith<DonorRuntimeException.Unavailable> {
            rig.owner.start("approved.profile", Instant.now())
        }

        assertEquals(1, rig.serverFactory.servers.single().closeCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
        assertEquals(DonorRuntimeStopResult.ALREADY_STOPPED, rig.owner.stopUntil(400L))
    }
}
