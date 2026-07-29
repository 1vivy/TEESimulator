package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DonorServiceStartDispatcherTest {
    @Test
    fun invalidExplicitStartForegroundsBeforeCleanupWithoutRuntimeAccess() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.host.stopsFinished = CountDownLatch(1)

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, "../profile", 40))

            rig.host.stopsFinished.awaitTest()
            assertEquals(
                listOf("foreground-start", "stop-self:40", "foreground-remove"),
                rig.events.toList(),
            )
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(0, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
        }
    }

    @Test
    fun missingExplicitStartAlsoForegroundsThenStopsOnlyThatRequest() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.host.stopsFinished = CountDownLatch(1)

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, null, 41))

            rig.host.stopsFinished.awaitTest()
            assertEquals(listOf(41), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(0, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
        }
    }

    @Test
    fun validExplicitStartForegroundsOnceAndThenRunsNormally() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startsFinished = CountDownLatch(1)

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 42))

            rig.runtime.startsFinished.awaitTest()
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(
                listOf("foreground-start", "runtime-start:approved.profile"),
                rig.events.toList(),
            )
        }
    }

    @Test
    fun invalidStartCannotTearDownAnActiveValidRuntime() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startsFinished = CountDownLatch(1)
            dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 45)
            rig.runtime.startsFinished.awaitTest()

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, null, 46))

            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(0, rig.host.stopCalls.get())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
            assertEquals("approved.profile", rig.runtime.activeProfileId)
        }
    }

    @Test
    fun invalidStartCannotSupersedePendingValidStartFailureCleanup() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startEntered = CountDownLatch(1)
            rig.runtime.releaseStart = CountDownLatch(1)
            rig.runtime.startsFinished = CountDownLatch(1)
            rig.runtime.startFailure = DonorRuntimeException.Unavailable()
            rig.runtime.startFailureState = DonorRuntimeState.STOPPED
            rig.host.stopsFinished = CountDownLatch(1)
            dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 47)
            rig.runtime.startEntered.awaitTest()

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, "../profile", 48))
            val stopsBeforeOriginalCompleted = rig.host.stopCalls.get()
            rig.runtime.releaseStart.countDown()
            rig.runtime.startsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()

            assertEquals(0, stopsBeforeOriginalCompleted)
            assertEquals(listOf(48), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
            assertEquals(DonorRuntimeState.STOPPED, rig.runtime.state)
            assertEquals(null, rig.runtime.activeProfileId)
        }
    }

    @Test
    fun inertDeliveryBeforeQueuedFailureCleanupSuppliesLatestStartId() {
        val callbacks = QueuedCallbackExecutor()
        DonorServiceControllerRig(callbackExecutor = callbacks).use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startEntered = CountDownLatch(1)
            rig.runtime.releaseStart = CountDownLatch(1)
            rig.runtime.startsFinished = CountDownLatch(1)
            rig.runtime.startFailure = DonorRuntimeException.Unavailable()
            rig.runtime.startFailureState = DonorRuntimeState.STOPPED
            dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 47)
            rig.runtime.startEntered.awaitTest()
            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, "../profile", 48))
            rig.runtime.releaseStart.countDown()
            rig.runtime.startsFinished.awaitTest()
            val workerDrained = CountDownLatch(1)
            rig.worker.execute { workerDrained.countDown() }
            workerDrained.awaitTest()

            assertTrue(dispatcher.dispatch(null, null, 49))
            callbacks.runAll()

            assertEquals(listOf(49), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.host.removeForegroundCalls.get())
        }
    }

    @Test
    fun invalidStartWaitsForPendingSuccessfulStopBeforeForegroundRemoval() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startsFinished = CountDownLatch(1)
            dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 49)
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopEntered = CountDownLatch(1)
            rig.runtime.releaseStop = CountDownLatch(1)
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.host.stopsFinished = CountDownLatch(1)
            rig.controller.handle(DonorServiceCommand.Stop, 50)
            rig.runtime.stopEntered.awaitTest()

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, null, 51))
            val stopsBeforeStopCompleted = rig.host.stopCalls.get()
            rig.runtime.releaseStop.countDown()
            rig.runtime.stopsFinished.awaitTest()
            rig.host.stopsFinished.awaitTest()

            assertEquals(0, stopsBeforeStopCompleted)
            assertEquals(listOf(51), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(1, rig.runtime.stopCalls.get())
            assertEquals(DonorRuntimeState.STOPPED, rig.runtime.state)
            assertEquals(null, rig.runtime.activeProfileId)
        }
    }

    @Test
    fun invalidStartAfterFailedStopRetainsForeground() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)
            rig.runtime.startsFinished = CountDownLatch(1)
            dispatcher.dispatch(DonorService.ACTION_START, "approved.profile", 52)
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopEntered = CountDownLatch(1)
            rig.runtime.releaseStop = CountDownLatch(1)
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.runtime.stopFailure = TestServiceFailure()
            rig.controller.handle(DonorServiceCommand.Stop, 53)
            rig.runtime.stopEntered.awaitTest()

            assertTrue(dispatcher.dispatch(DonorService.ACTION_START, "../profile", 54))
            val stopsBeforeStopCompleted = rig.host.stopCalls.get()
            val workerDrained = CountDownLatch(1)
            rig.worker.execute { workerDrained.countDown() }
            rig.runtime.releaseStop.countDown()
            rig.runtime.stopsFinished.awaitTest()
            workerDrained.awaitTest()

            assertEquals(0, stopsBeforeStopCompleted)
            assertEquals(0, rig.host.stopCalls.get())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(1, rig.runtime.stopCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
            assertEquals("approved.profile", rig.runtime.activeProfileId)
            rig.runtime.stopFailure = null
        }
    }

    @Test
    fun nullAndUnknownActionsRemainInert() {
        DonorServiceControllerRig().use { rig ->
            val dispatcher = DonorServiceStartDispatcher(rig.controller)

            assertTrue(dispatcher.dispatch(null, null, 43))
            assertTrue(dispatcher.dispatch("unknown.action", "approved.profile", 44))

            assertEquals(0, rig.host.foregroundCalls.get())
            assertEquals(0, rig.host.stopCalls.get())
            assertEquals(0, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
        }
    }
}
