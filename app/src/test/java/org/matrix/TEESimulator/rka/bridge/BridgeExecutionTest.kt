package org.matrix.TEESimulator.rka.bridge

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeExecutionTest {
    @Test
    fun four_active_four_queued_and_ninth_rejected_use_the_production_executor() {
        val executor = executor(4, 4)
        val execution = BoundedBridgeExecution(executor)
        val release = CountDownLatch(1)
        val callers =
            List(8) {
                Thread {
                        execution.run(2_000, {}) {
                            release.await()
                            BridgeResult.Success(Unit)
                        }
                    }
                    .apply { start() }
            }
        waitUntil { execution.activeCount() == 4 && execution.queuedCount() == 4 }

        val ninth = execution.run(2_000, {}) { BridgeResult.Success(Unit) }

        assertEquals(BridgeError.QueueSaturated, (ninth as BridgeResult.Failure).error)
        release.countDown()
        callers.forEach { it.join(1_000) }
        assertTrue(callers.none(Thread::isAlive))
        waitUntil { execution.activeCount() == 0 && execution.queuedCount() == 0 }
        executor.shutdown()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
    }

    @Test
    fun timeout_aborts_exact_work_and_leaves_no_active_or_queued_task() {
        val executor = executor(1, 1)
        val execution = BoundedBridgeExecution(executor)
        val release = CountDownLatch(1)
        val aborts = AtomicInteger()
        val started = System.nanoTime()

        val result =
            execution.run(
                50,
                {
                    aborts.incrementAndGet()
                    release.countDown()
                },
            ) {
                release.await()
                BridgeResult.Success(Unit)
            }
        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

        assertEquals(BridgeError.DeadlineExceeded, (result as BridgeResult.Failure).error)
        assertTrue("timeout took $elapsed ms", elapsed < 500)
        assertEquals(1, aborts.get())
        waitUntil { execution.activeCount() == 0 && execution.queuedCount() == 0 }
        executor.shutdown()
        assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS))
    }

    private fun executor(active: Int, queued: Int) =
        ThreadPoolExecutor(
            active,
            active,
            0,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(queued),
            ThreadPoolExecutor.AbortPolicy(),
        )

    private fun waitUntil(predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (!predicate() && System.nanoTime() < deadline) Thread.yield()
        assertTrue(predicate())
    }
}
