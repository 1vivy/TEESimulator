package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DonorServiceControllerCloseTest {
    @Test
    fun rejectedCloseSubmissionIsIncompleteWithoutCallerThreadRuntimeStop() {
        val runtime = FakeServiceRuntime().apply { state = DonorRuntimeState.RUNNING }
        val worker = RejectingDonorServiceExecutor()
        val rig = DonorServiceControllerRig(runtime = runtime, worker = worker)

        val outcome = rig.controller.closeAndReport()

        assertEquals(DonorServiceCloseOutcome.INCOMPLETE, outcome)
        assertEquals(0, runtime.stopCalls.get())
        assertTrue(worker.isTerminated)
    }

    @Test
    fun quickIncompleteStopRetriesOnceAndClosesWithOneSharedDeadline() {
        val runtime =
            FakeServiceRuntime().apply {
                state = DonorRuntimeState.RUNNING
                stopFailuresRemaining.set(1)
                stopsFinished = CountDownLatch(2)
            }
        val rig = DonorServiceControllerRig(runtime = runtime)

        val outcome = rig.controller.closeAndReport()

        assertEquals(DonorServiceCloseOutcome.CLOSED, outcome)
        assertEquals(2, runtime.stopCalls.get())
        assertEquals(1, runtime.stopDeadlines.distinct().size)
        assertTrue(runtime.stopThreadNames.all { it == "donor-service-controller-test" })
    }

    @Test
    fun firstConfirmedStopClosesWithoutRetry() {
        val runtime = FakeServiceRuntime().apply { state = DonorRuntimeState.RUNNING }
        val rig = DonorServiceControllerRig(runtime = runtime)

        assertEquals(DonorServiceCloseOutcome.CLOSED, rig.controller.closeAndReport())

        assertEquals(1, runtime.stopCalls.get())
        assertEquals(1, runtime.stopDeadlines.size)
    }

    @Test
    fun blockedStopPastSharedDeadlineIsIncomplete() {
        val runtime =
            FakeServiceRuntime().apply {
                state = DonorRuntimeState.RUNNING
                stopEntered = CountDownLatch(1)
                releaseStop = CountDownLatch(1)
            }
        val rig = DonorServiceControllerRig(runtime = runtime, shutdownTimeoutMillis = 50)

        try {
            assertEquals(DonorServiceCloseOutcome.INCOMPLETE, rig.controller.closeAndReport())
            assertEquals(1, runtime.stopCalls.get())
        } finally {
            runtime.releaseStop.countDown()
        }
    }

    @Test
    fun concurrentCloseCallersShareOneTaskDeadlineAndOutcome() {
        val runtime = FakeServiceRuntime().apply { state = DonorRuntimeState.RUNNING }
        val rig = DonorServiceControllerRig(runtime = runtime)
        val callers = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        try {
            val closes =
                List(24) {
                    callers.submit<DonorServiceCloseOutcome> {
                        start.await()
                        rig.controller.closeAndReport()
                    }
                }
            start.countDown()

            assertEquals(
                setOf(DonorServiceCloseOutcome.CLOSED),
                closes.map { it.get(5, TimeUnit.SECONDS) }.toSet(),
            )
            assertEquals(1, runtime.stopCalls.get())
            assertEquals(1, runtime.stopDeadlines.distinct().size)
        } finally {
            callers.shutdownNow()
            assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun interruptedCloseWaitRestoresInterruptionAfterSharedOutcome() {
        val runtime =
            FakeServiceRuntime().apply {
                state = DonorRuntimeState.RUNNING
                stopEntered = CountDownLatch(1)
                releaseStop = CountDownLatch(1)
            }
        val rig = DonorServiceControllerRig(runtime = runtime)
        val firstOutcome = AtomicReference<DonorServiceCloseOutcome>()
        val first = Thread { firstOutcome.set(rig.controller.closeAndReport()) }
        first.start()
        runtime.stopEntered.awaitTest()
        val secondOutcome = AtomicReference<DonorServiceCloseOutcome>()
        val restored = AtomicBoolean()
        val second = Thread {
            secondOutcome.set(rig.controller.closeAndReport())
            restored.set(Thread.currentThread().isInterrupted)
        }
        second.interrupt()
        second.start()

        runtime.releaseStop.countDown()
        first.join(5_000)
        second.join(5_000)

        assertEquals(DonorServiceCloseOutcome.CLOSED, firstOutcome.get())
        assertEquals(DonorServiceCloseOutcome.CLOSED, secondOutcome.get())
        assertTrue(restored.get())
        assertEquals(1, runtime.stopCalls.get())
    }

    @Test
    fun acceptedWorkPrecedesCloseTaskAndLaterCommandsReject() {
        val rig = DonorServiceControllerRig()
        val blockerEntered = CountDownLatch(1)
        val releaseBlocker = CountDownLatch(1)
        rig.worker.execute {
            blockerEntered.countDown()
            releaseBlocker.await()
        }
        blockerEntered.awaitTest()
        rig.runtime.startsFinished = CountDownLatch(1)
        rig.runtime.stopsFinished = CountDownLatch(1)
        assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 300))
        val closeOutcome = AtomicReference<DonorServiceCloseOutcome>()
        val closer = Thread { closeOutcome.set(rig.controller.closeAndReport()) }
        closer.start()

        val rejectionDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (rig.controller.handle(DonorServiceCommand.Inert, 301)) {
            check(System.nanoTime() < rejectionDeadline)
            Thread.yield()
        }
        assertFalse(rig.controller.handle(DonorServiceCommand.Stop, 302))
        releaseBlocker.countDown()
        closer.join(5_000)

        assertEquals(DonorServiceCloseOutcome.CLOSED, closeOutcome.get())
        assertEquals(
            listOf("foreground-start", "runtime-start:approved.profile", "runtime-stop"),
            rig.events.toList(),
        )
    }

    @Test
    fun incompleteConcurrentCloseOrTerminateInvokesTerminatorExactlyOnceBeforeForegroundRemoval() {
        val runtime =
            FakeServiceRuntime().apply {
                state = DonorRuntimeState.RUNNING
                stopFailure = TestServiceFailure()
            }
        val rig = DonorServiceControllerRig(runtime = runtime)
        rig.runtime.startsFinished = CountDownLatch(1)
        assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 302))
        rig.runtime.startsFinished.awaitTest()
        val callers = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        try {
            val closes =
                List(24) {
                    callers.submit {
                        start.await()
                        rig.controller.closeOrTerminate()
                    }
                }
            start.countDown()
            val terminations =
                closes.mapNotNull { close ->
                    try {
                        close.get(5, TimeUnit.SECONDS)
                        null
                    } catch (failure: ExecutionException) {
                        failure.cause
                    }
                }

            assertEquals(1, terminations.size)
            assertIs<TestDonorProcessTermination>(terminations.single())
            assertEquals(1, rig.host.terminateProcessCalls.get())
            assertEquals(0, rig.host.removeForegroundCalls.get())
            assertEquals(2, runtime.stopCalls.get())
        } finally {
            callers.shutdownNow()
            assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}
