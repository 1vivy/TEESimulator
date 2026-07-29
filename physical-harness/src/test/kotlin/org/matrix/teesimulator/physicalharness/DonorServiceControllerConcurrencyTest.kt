package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DonorServiceControllerConcurrencyTest {
    @Test
    fun concurrentStartsWaitForOneSuccessfulForegroundEntryBeforeRuntimeSubmission() {
        DonorServiceControllerRig().use { rig ->
            rig.host.foregroundEntered = CountDownLatch(1)
            rig.host.releaseForeground = CountDownLatch(1)
            rig.runtime.startsFinished = CountDownLatch(2)
            val callers = Executors.newFixedThreadPool(2)
            try {
                val first =
                    callers.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 200)
                    }
                rig.host.foregroundEntered.awaitTest()
                val second =
                    callers.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 201)
                    }

                assertBlocked(second)
                assertEquals(0, rig.runtime.startCalls.get())
                rig.host.releaseForeground.countDown()

                assertTrue(first.get(5, TimeUnit.SECONDS))
                assertTrue(second.get(5, TimeUnit.SECONDS))
                rig.runtime.startsFinished.awaitTest()
                assertEquals(1, rig.host.foregroundCalls.get())
                assertEquals(2, rig.runtime.startCalls.get())
                assertEquals(1, rig.runtime.maxConcurrentCalls.get())
            } finally {
                rig.host.releaseForeground.countDown()
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun failedForegroundEntryPublishesSameFailureAndSubmitsNoRuntimeWork() {
        DonorServiceControllerRig().use { rig ->
            val failure = TestServiceFailure()
            rig.host.foregroundFailure = failure
            rig.host.foregroundEntered = CountDownLatch(1)
            rig.host.releaseForeground = CountDownLatch(1)
            val callers = Executors.newFixedThreadPool(2)
            try {
                val first =
                    callers.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 202)
                    }
                rig.host.foregroundEntered.awaitTest()
                val second =
                    callers.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 203)
                    }
                assertBlocked(second)

                rig.host.releaseForeground.countDown()

                assertSame(
                    failure,
                    assertFailsWith<ExecutionException> { first.get(5, TimeUnit.SECONDS) }.cause,
                )
                assertSame(
                    failure,
                    assertFailsWith<ExecutionException> { second.get(5, TimeUnit.SECONDS) }.cause,
                )
                assertEquals(1, rig.host.foregroundCalls.get())
                assertEquals(0, rig.runtime.startCalls.get())
            } finally {
                rig.host.releaseForeground.countDown()
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun interruptedForegroundWaitCompletesThenRestoresInterruption() {
        DonorServiceControllerRig().use { rig ->
            rig.host.foregroundEntered = CountDownLatch(1)
            rig.host.releaseForeground = CountDownLatch(1)
            rig.runtime.startsFinished = CountDownLatch(2)
            val owner = Thread {
                rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 210)
            }
            owner.start()
            rig.host.foregroundEntered.awaitTest()
            val waiterFinished = CountDownLatch(1)
            val interruptionRestored = AtomicBoolean()
            val waiter = Thread {
                try {
                    rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 211)
                } finally {
                    interruptionRestored.set(Thread.currentThread().isInterrupted)
                    waiterFinished.countDown()
                }
            }
            waiter.interrupt()
            waiter.start()

            assertTrue(!waiterFinished.await(100, TimeUnit.MILLISECONDS))
            rig.host.releaseForeground.countDown()
            owner.join(5_000)
            waiter.join(5_000)
            rig.runtime.startsFinished.awaitTest()

            assertTrue(interruptionRestored.get())
            assertEquals(1, rig.host.foregroundCalls.get())
            assertEquals(2, rig.runtime.startCalls.get())
        }
    }

    @Test
    fun startDuringFailedStopSelfWaitsThenReusesActiveForeground() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 204))
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.host.stopSelfResults += false
            rig.host.stopSelfEntered = CountDownLatch(1)
            rig.host.releaseStopSelf = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Stop, 205))
            rig.runtime.stopsFinished.awaitTest()
            rig.host.stopSelfEntered.awaitTest()
            rig.runtime.startsFinished = CountDownLatch(1)
            val caller = Executors.newSingleThreadExecutor()
            try {
                val start =
                    caller.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 206)
                    }
                assertBlocked(start)

                rig.host.releaseStopSelf.countDown()

                assertTrue(start.get(5, TimeUnit.SECONDS))
                rig.runtime.startsFinished.awaitTest()
                assertEquals(1, rig.host.foregroundCalls.get())
                assertEquals(1, rig.host.stopCalls.get())
                assertEquals(0, rig.host.removeForegroundCalls.get())
            } finally {
                rig.host.releaseStopSelf.countDown()
                caller.shutdownNow()
                assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun startDuringSuccessfulRemovalWaitsThenPerformsFreshForegroundEntry() {
        DonorServiceControllerRig().use { rig ->
            rig.runtime.startsFinished = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 207))
            rig.runtime.startsFinished.awaitTest()
            rig.runtime.stopsFinished = CountDownLatch(1)
            rig.host.removeForegroundEntered = CountDownLatch(1)
            rig.host.releaseRemoveForeground = CountDownLatch(1)
            assertTrue(rig.controller.handle(DonorServiceCommand.Stop, 208))
            rig.runtime.stopsFinished.awaitTest()
            rig.host.removeForegroundEntered.awaitTest()
            rig.runtime.startsFinished = CountDownLatch(1)
            val caller = Executors.newSingleThreadExecutor()
            try {
                val start =
                    caller.submit<Boolean> {
                        rig.controller.handle(DonorServiceCommand.Start("approved.profile"), 209)
                    }
                assertBlocked(start)

                rig.host.releaseRemoveForeground.countDown()

                assertTrue(start.get(5, TimeUnit.SECONDS))
                rig.runtime.startsFinished.awaitTest()
                assertEquals(2, rig.host.foregroundCalls.get())
                assertEquals(1, rig.host.removeForegroundCalls.get())
            } finally {
                rig.host.releaseRemoveForeground.countDown()
                caller.shutdownNow()
                assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun concurrentHandleCallsRemainSerializedOnOneWorker() {
        DonorServiceControllerRig().use { rig ->
            val requests = 24
            rig.runtime.startsFinished = CountDownLatch(requests)
            val start = CountDownLatch(1)
            val callers = Executors.newFixedThreadPool(8)
            try {
                val accepted =
                    List(requests) { index ->
                        callers.submit<Boolean> {
                            start.await()
                            rig.controller.handle(
                                DonorServiceCommand.Start("profile-$index"),
                                100 + index,
                            )
                        }
                    }
                start.countDown()

                assertTrue(accepted.all { it.get(5, TimeUnit.SECONDS) })
                rig.runtime.startsFinished.awaitTest()
                assertEquals(1, rig.runtime.maxConcurrentCalls.get())
                assertEquals(requests, rig.runtime.startCalls.get())
                assertEquals(1, rig.host.foregroundCalls.get())
            } finally {
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    private fun assertBlocked(future: Future<*>) {
        assertFailsWith<TimeoutException> { future.get(100, TimeUnit.MILLISECONDS) }
    }
}
