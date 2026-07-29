package org.matrix.teesimulator.physicalharness

import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SocketDeadlineSchedulerTest {
    @Test
    fun incompleteCloseRetriesUntilBlockedDeadlineTaskTerminates() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val scheduler = SocketDeadlineScheduler()
        val socket =
            object : Socket() {
                override fun close() {
                    entered.countDown()
                    while (release.count > 0) {
                        try {
                            release.await()
                        } catch (_: InterruptedException) {
                            continue
                        }
                    }
                }
            }
        scheduler.run(socket, 0) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }

        val first = scheduler.closeUntil(System.nanoTime())

        assertEquals(DeadlineShutdownResult(terminated = false, interrupted = false), first)
        assertFalse(scheduler.isTerminated)
        release.countDown()

        val second = scheduler.closeUntil(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))

        assertEquals(DeadlineShutdownResult(terminated = true, interrupted = false), second)
        assertTrue(scheduler.isTerminated)
        assertEquals(
            DeadlineShutdownResult(terminated = true, interrupted = false),
            scheduler.closeUntil(System.nanoTime()),
        )
    }
}
