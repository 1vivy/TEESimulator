package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DonorServiceControllerFailureTest {
    @Test
    fun foregroundFailureQueuesNoRuntimeWorkAndControllerCanRetry() {
        DonorServiceControllerRig().use { rig ->
            rig.host.foregroundFailure = TestServiceFailure()
            assertFailsWith<TestServiceFailure> {
                rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 30)
            }
            assertEquals(0, rig.runtime.startCalls.get())

            rig.host.foregroundFailure = null
            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 31))
            rig.runtime.startsFinished.awaitTest()
            assertEquals(1, rig.runtime.startCalls.get())
        }
    }

    @Test
    fun runtimeStartFailureDoesNotLeakWorkerAndAReplacementStartCanRun() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startFailure = TestServiceFailure()
            rig.runtime.startsFinished = CountDownLatch(1)
            rig.host.stopsFinished = CountDownLatch(1)
            rig.controller.handle(DonorServiceCommand.Start("unknown.profile"), 34)
            rig.runtime.startsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()

            rig.runtime.startFailure = null
            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 35))
            rig.runtime.startsFinished.awaitTest()

            assertEquals(2, rig.runtime.startCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
        }
    }

    @Test
    fun callbackAndRuntimeStopFailuresDoNotEscapeOrPreventShutdown() {
        val rig = DonorServiceControllerRig()
        rig.host.stopSelfFailure = TestServiceFailure()
        rig.runtime.stopsFinished = CountDownLatch(1)
        rig.host.stopsFinished = CountDownLatch(1)

        assertTrue(rig.controller.handle(DonorServiceCommand.Stop, 32))
        rig.runtime.stopsFinished.awaitTest()
        rig.host.stopsFinished.awaitTest()
        rig.controller.close()

        assertTrue(rig.worker.isTerminated)
        assertFalse(rig.controller.handle(DonorServiceCommand.Stop, 33))
    }

    @Test
    fun ordinaryStopFailureRetainsForegroundAndActiveRuntime() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(1)
            rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 36)
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopFailure = TestServiceFailure()
            rig.runtime.stopsFinished = CountDownLatch(1)
            val workerDrained = CountDownLatch(1)

            assertTrue(rig.controller.handle(DonorServiceCommand.Stop, 37))
            rig.worker.execute { workerDrained.countDown() }
            rig.runtime.stopsFinished.awaitTest()
            workerDrained.awaitTest()

            assertEquals(0, rig.host.stopCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
            assertEquals("approved.profile", rig.runtime.activeProfileId)
            rig.runtime.stopFailure = null
        }
    }

    @Test
    fun ordinarySuccessfulStopRemovesForeground() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(1)
            rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 38)
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.host.stopsFinished = CountDownLatch(1)

            assertTrue(rig.controller.handle(DonorServiceCommand.Stop, 39))
            rig.runtime.stopsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()

            assertEquals(listOf(39), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.host.removeForegroundCalls.get())
            assertEquals(DonorRuntimeState.STOPPED, rig.runtime.state)
            assertEquals(null, rig.runtime.activeProfileId)
        }
    }

    @Test
    fun falseStopSelfRetainsForegroundAndDoesNotRemoveIt() {
        DonorServiceControllerRig().use { rig ->
            rig.host.stopSelfResults += false
            rig.host.stopSelfAttemptsFinished = CountDownLatch(1)
            rig.host.stopsFinished = CountDownLatch(1)

            assertTrue(rig.controller.handleExplicitStart(null, 60))
            rig.host.stopSelfAttemptsFinished.awaitTest()

            assertEquals(listOf(60), rig.host.stoppedStartIds.toList())
            assertEquals(0, rig.host.removeForegroundCalls.get())

            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 61))
            rig.runtime.startsFinished.awaitTest()
            assertEquals(1, rig.host.foregroundCalls.get())
        }
    }

    @Test
    fun removalFailurePreservesConservativeForegroundState() {
        DonorServiceControllerRig().use { rig ->
            rig.host.removeForegroundFailure = TestServiceFailure()
            rig.host.removalsFinished = CountDownLatch(1)

            assertTrue(rig.controller.handleExplicitStart(null, 62))
            rig.host.removalsFinished.awaitTest()

            rig.host.removeForegroundFailure = null
            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 63))
            rig.runtime.startsFinished.awaitTest()
            assertEquals(1, rig.host.foregroundCalls.get())
        }
    }
}
