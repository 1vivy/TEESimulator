package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DonorServiceControllerStartTest {
    @Test
    fun inertAndInvalidCommandsNeverTouchForegroundOrRuntime() {
        DonorServiceControllerRig().use { rig ->
            assertTrue(rig.controller.handle(DonorServiceCommand.Inert, 1))
            listOf(null, "", "../profile").forEach { profileId ->
                assertFailsWith<DonorServiceCommandException.InvalidStart> {
                    DonorServiceCommand.parse(DonorService.ACTION_START, profileId)
                }
            }

            assertEquals(0, rig.host.foregroundCalls.get())
            assertEquals(0, rig.runtime.startCalls.get())
            assertEquals(0, rig.runtime.stopCalls.get())
        }
    }

    @Test
    fun foregroundStartsSynchronouslyBeforeBlockedRuntimeWork() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startEntered = CountDownLatch(1)
            rig.runtime.releaseStart = CountDownLatch(1)
            rig.runtime.startsFinished = CountDownLatch(1)

            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 10))

            assertEquals(1, rig.host.foregroundCalls.get())
            rig.runtime.startEntered.awaitTest()
            assertEquals(
                listOf("foreground-start", "runtime-start:approved.profile"),
                rig.events.toList(),
            )
            rig.runtime.releaseStart.countDown()
            rig.runtime.startsFinished.awaitTest()
        }
    }

    @Test
    fun stoppedStartFailureRemovesOnlyThatForegroundRequest() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startFailure = DonorRuntimeException.Unavailable()
            rig.runtime.startFailureState = DonorRuntimeState.STOPPED
            rig.host.stopsFinished = CountDownLatch(1)

            rig.controller.handle(DonorServiceCommand.Start("unknown.profile"), 11)

            rig.host.stopsFinished.awaitTest()
            assertEquals(listOf(11), rig.host.stoppedStartIds.toList())
            assertEquals(1, rig.runtime.startCalls.get())
            assertEquals(DonorRuntimeState.STOPPED, rig.runtime.state)
        }
    }

    @Test
    fun repeatedSameProfileStartIsIdempotentAndKeepsForeground() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(2)

            rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 12)
            rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 13)

            rig.runtime.startsFinished.awaitTest()
            assertEquals(2, rig.runtime.startCalls.get())
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(0, rig.host.stopCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
        }
    }

    @Test
    fun conflictingStartPreservesTheOriginalRuntimeAndForeground() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(2)

            rig.controller.handle(DonorServiceCommand.Start("original.profile"), 14)
            rig.controller.handle(DonorServiceCommand.Start("other.profile"), 15)

            rig.runtime.startsFinished.awaitTest()
            assertEquals("original.profile", rig.runtime.activeProfileId)
            assertEquals(DonorRuntimeState.RUNNING, rig.runtime.state)
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(0, rig.host.stopCalls.get())
        }
    }
}
