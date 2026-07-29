package org.matrix.teesimulator.physicalharness

import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

internal data class DeadlineShutdownResult(val terminated: Boolean, val interrupted: Boolean)

internal data class DeadlineLockResult(val acquired: Boolean, val interrupted: Boolean)

internal fun ReentrantLock.tryLockUntil(deadlineNanos: Long): DeadlineLockResult {
    var interrupted = false
    while (true) {
        try {
            val remainingNanos = remainingNanosUntil(deadlineNanos)
            val acquired =
                if (remainingNanos == 0L) tryLock()
                else tryLock(remainingNanos, TimeUnit.NANOSECONDS)
            return DeadlineLockResult(acquired, interrupted)
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
}

internal fun awaitThreadUntil(thread: Thread?, deadlineNanos: Long): DeadlineShutdownResult {
    var interrupted = false
    while (thread?.isAlive == true) {
        val remainingNanos = remainingNanosUntil(deadlineNanos)
        if (remainingNanos == 0L) break
        try {
            val millis = TimeUnit.NANOSECONDS.toMillis(remainingNanos)
            val nanos = (remainingNanos - TimeUnit.MILLISECONDS.toNanos(millis)).toInt()
            thread.join(millis, nanos)
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    return DeadlineShutdownResult(thread?.isAlive != true, interrupted)
}

internal fun awaitExecutorUntil(
    executor: ExecutorService,
    deadlineNanos: Long,
): DeadlineShutdownResult {
    var interrupted = false
    while (!executor.isTerminated) {
        val remainingNanos = remainingNanosUntil(deadlineNanos)
        if (remainingNanos == 0L) break
        try {
            executor.awaitTermination(remainingNanos, TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    return DeadlineShutdownResult(executor.isTerminated, interrupted)
}

private fun remainingNanosUntil(deadlineNanos: Long): Long {
    val remainingNanos = deadlineNanos - System.nanoTime()
    return if (remainingNanos > 0L) remainingNanos else 0L
}
