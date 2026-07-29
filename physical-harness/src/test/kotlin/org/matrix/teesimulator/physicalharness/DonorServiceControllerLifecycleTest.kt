package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DonorServiceControllerLifecycleTest {
    @Test
    fun startThenStopRunsExactlyOnceEachInWorkerOrder() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.host.stopsFinished = CountDownLatch(1)

            rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 20)
            rig.controller.handle(DonorServiceCommand.Stop, 21)

            rig.runtime.stopsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()
            assertEquals(
                listOf(
                    "foreground-start",
                    "runtime-start:approved.profile",
                    "runtime-stop",
                    "stop-self:21",
                    "foreground-remove",
                ),
                rig.events.toList(),
            )
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(1, rig.runtime.stopCalls.get())
        }
    }

    @Test
    fun repeatedStopIsSafeAndLatestRequestOwnsForegroundRemoval() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.stopsFinished = CountDownLatch(2)
            rig.host.stopsFinished = CountDownLatch(1)

            rig.controller.handle(DonorServiceCommand.Stop, 22)
            rig.controller.handle(DonorServiceCommand.Stop, 23)

            rig.runtime.stopsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()
            assertEquals(2, rig.runtime.stopCalls.get())
            assertEquals(listOf(23), rig.host.stoppedStartIds.toList())
        }
    }

    @Test
    fun newerDeliveredIdRetriesFalseStopSelfOnceBeforeForegroundRemoval() {
        DonorServiceControllerRig().use { rig ->
            rig.host.stopSelfResults += listOf(false, true)
            rig.host.stopSelfEntered = CountDownLatch(1)
            rig.host.releaseStopSelf = CountDownLatch(1)
            rig.host.stopSelfAttemptsFinished = CountDownLatch(2)
            rig.host.removalsFinished = CountDownLatch(1)

            assertTrue(rig.controller.handleExplicitStart(null, 64))
            rig.host.stopSelfEntered.awaitTest()
            assertTrue(rig.controller.handle(DonorServiceCommand.Inert, 65))
            rig.host.releaseStopSelf.countDown()
            rig.host.stopSelfAttemptsFinished.awaitTest()
            rig.host.removalsFinished.awaitTest()

            assertEquals(listOf(64, 65), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.host.removeForegroundCalls.get())
            assertEquals(
                listOf("foreground-start", "stop-self:64", "stop-self:65", "foreground-remove"),
                rig.events.toList(),
            )

            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 66))
            rig.runtime.startsFinished.awaitTest()
            assertEquals(2, rig.host.foregroundCalls.get())
        }
    }
}
