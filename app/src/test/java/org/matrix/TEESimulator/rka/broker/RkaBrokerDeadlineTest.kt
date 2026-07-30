package org.matrix.TEESimulator.rka.broker

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RkaBrokerDeadlineTest {
    @Test
    fun inspectConsumesOneAggregateBudgetAcrossBothServices() {
        val clock = FakeMonotonicClock()
        val resolver = FakeResolver()
        val runner =
            AdvancingCallRunner(
                clock,
                TimeUnit.MILLISECONDS.toNanos(2_700),
                TimeUnit.MILLISECONDS.toNanos(2_700),
            )

        val outcome =
            BrokerCapability.forResolver(resolver, runner)
                .inspect(
                    BrokerCaller.external(10_042, 0),
                    BrokerDeadline.at(5_000, clock),
                    BrokerCancellation.active(),
        )

        assertEquals(BrokerError.DeadlineExceeded, (outcome as BrokerOutcome.Failure).error)
    }

    @Test
    fun deadlineExpiresAtExactBoundaryAcrossNanoTimeOverflow() {
        val fiveMillis = TimeUnit.MILLISECONDS.toNanos(5)
        val clock = FakeMonotonicClock(Long.MAX_VALUE - fiveMillis + 1)
        val deadline = BrokerDeadline.at(5, clock)

        assertEquals(fiveMillis, deadline.remainingNanos())
        clock.advanceNanos(fiveMillis - 1)
        assertEquals(1, deadline.remainingNanos())
        clock.advanceNanos(1)

        assertEquals(0, deadline.remainingNanos())
    }

    @Test
    fun backwardClockReadingFailsClosedInsteadOfExtendingBudget() {
        val clock = FakeMonotonicClock(100)
        val deadline = BrokerDeadline.at(5, clock)

        clock.setNanos(99)

        assertTrue(deadline.hasExpired())
        assertEquals(0, deadline.remainingNanos())
    }

    @Test
    fun expiredQueuedCallIsRemovedAndNeverStarts() {
        val workerRelease = CountDownLatch(1)
        val queued = CountDownLatch(1)
        val callStarted = AtomicBoolean(false)
        val clock = FakeMonotonicClock()
        val executor = queueObservingExecutor(queued)
        executor.submit { workerRelease.await() }
        val outcome = AtomicReference<BrokerOutcome<Unit>>()
        val caller =
            Thread {
                    outcome.set(
                        ExecutorBrokerCallRunner(executor).run(
                            BrokerServiceKind.IRPC,
                            BrokerDeadline.at(5, clock),
                            BrokerCancellation.active(),
                        ) {
                            callStarted.set(true)
                        }
                    )
                }
                .apply { start() }

        assertTrue(queued.await(1, TimeUnit.SECONDS))
        clock.advanceNanos(TimeUnit.MILLISECONDS.toNanos(5))
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertEquals(BrokerError.DeadlineExceeded, failure(outcome.get()))
        assertFalse(callStarted.get())
        assertTrue(executor.queue.isEmpty())
        workerRelease.countDown()
        executor.shutdownNow()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
    }

    @Test
    fun cancellationWinningCompletionRaceDiscardsResultAndStopsWorker() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val cancellation = BrokerCancellation.active()
        val executor = singleWorkerExecutor()
        val outcome = AtomicReference<BrokerOutcome<Int>>()
        val caller =
            Thread {
                    outcome.set(
                        ExecutorBrokerCallRunner(executor).run(
                            BrokerServiceKind.IRPC,
                            BrokerDeadline.at(5_000),
                            cancellation,
                        ) {
                            entered.countDown()
                            release.await()
                            42
                        }
                    )
                }
                .apply { start() }

        assertTrue(entered.await(1, TimeUnit.SECONDS))
        cancellation.cancel()
        release.countDown()
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertEquals(BrokerError.Cancelled, failure(outcome.get()))
        executor.shutdown()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
        assertEquals(0, executor.activeCount)
        assertTrue(executor.queue.isEmpty())
    }

    @Test
    fun timeoutWinningCompletionRaceDiscardsResult() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val clock = FakeMonotonicClock()
        val executor = singleWorkerExecutor()
        val outcome = AtomicReference<BrokerOutcome<Int>>()
        val caller =
            Thread {
                    outcome.set(
                        ExecutorBrokerCallRunner(executor).run(
                            BrokerServiceKind.IRPC,
                            BrokerDeadline.at(5, clock),
                            BrokerCancellation.active(),
                        ) {
                            entered.countDown()
                            release.await()
                            42
                        }
                    )
                }
                .apply { start() }

        assertTrue(entered.await(1, TimeUnit.SECONDS))
        clock.advanceNanos(TimeUnit.MILLISECONDS.toNanos(5))
        release.countDown()
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertEquals(BrokerError.DeadlineExceeded, failure(outcome.get()))
        executor.shutdownNow()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
    }

    @Test
    fun binderDeathWinningCompletionRaceDiscardsGeneratedMaterial() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val alive = AtomicBoolean(true)
        val executor = singleWorkerExecutor()
        val endpoint =
            FakeIrpcEndpoint(
                alive = alive,
                onGenerate = {
                    entered.countDown()
                    release.await()
                },
            )
        val client = IrpcClient(FakeResolver(irpc = endpoint), ExecutorBrokerCallRunner(executor))
        val outcome = AtomicReference<BrokerOutcome<IrpcKeyBatch>>()
        val caller =
            Thread {
                    outcome.set(
                        client.generateKeyBatch(
                            RkpKeyCount.parse(1).success(),
                            BrokerDeadline.at(5_000),
                            BrokerCancellation.active(),
                        )
                    )
                }
                .apply { start() }

        assertTrue(entered.await(1, TimeUnit.SECONDS))
        alive.set(false)
        release.countDown()
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertEquals(BrokerError.ServiceDead(BrokerServiceKind.IRPC), failure(outcome.get()))
        executor.shutdown()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
    }

    private fun queueObservingExecutor(queued: CountDownLatch): ThreadPoolExecutor =
        object :
            ThreadPoolExecutor(
                1,
                1,
                0,
                TimeUnit.MILLISECONDS,
                ArrayBlockingQueue(1),
            ) {
            override fun execute(command: Runnable) {
                super.execute(command)
                if (queue.contains(command)) queued.countDown()
            }
        }

    private fun singleWorkerExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(1),
        )

    private fun failure(outcome: BrokerOutcome<*>): BrokerError =
        (outcome as BrokerOutcome.Failure).error

    private fun <T> BrokerOutcome<T>.success(): T = (this as BrokerOutcome.Success).value

    private class FakeMonotonicClock(initialNanos: Long = 0) : BrokerMonotonicClock {
        private val now = AtomicLong(initialNanos)

        override fun nowNanos(): Long = now.get()

        fun advanceNanos(delta: Long) {
            now.addAndGet(delta)
        }

        fun setNanos(value: Long) {
            now.set(value)
        }
    }

    private class AdvancingCallRunner(
        private val clock: FakeMonotonicClock,
        vararg stageNanos: Long,
    ) : BrokerCallRunner {
        private val stages = stageNanos
        private val index = AtomicInteger()

        override fun <T> run(
            service: BrokerServiceKind,
            deadline: BrokerDeadline,
            cancellation: BrokerCancellation,
            call: () -> T,
        ): BrokerOutcome<T> {
            if (cancellation.isCancelled()) return BrokerOutcome.Failure(BrokerError.Cancelled)
            if (deadline.hasExpired()) {
                return BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
            }
            return try {
                val value = call()
                clock.advanceNanos(stages[index.getAndIncrement()])
                if (deadline.hasExpired()) {
                    BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
                } else {
                    BrokerOutcome.Success(value)
                }
            } catch (error: Throwable) {
                BrokerFailureMapper.map(service, error)
            }
        }
    }
}
