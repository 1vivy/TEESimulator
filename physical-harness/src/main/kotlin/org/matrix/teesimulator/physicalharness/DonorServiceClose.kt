package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

enum class DonorServiceCloseOutcome {
    CLOSED,
    INCOMPLETE,
}

internal class DonorServiceCloseAttempt(val deadlineNanos: Long) {
    private val finished = CountDownLatch(1)
    @Volatile private var outcome: DonorServiceCloseOutcome? = null
    @Volatile
    var runtimeStopConfirmed = false
        private set

    fun confirmRuntimeStopped() {
        runtimeStopConfirmed = true
    }

    fun complete(result: DonorServiceCloseOutcome) {
        check(outcome == null)
        outcome = result
        finished.countDown()
    }

    fun awaitOutcome(): DonorServiceCloseOutcome {
        var interrupted = false
        while (finished.count > 0) {
            try {
                finished.await()
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        try {
            return checkNotNull(outcome)
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}

internal fun serviceCloseDeadline(timeoutMillis: Long): Long {
    val nowNanos = System.nanoTime()
    val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
    return if (nowNanos > Long.MAX_VALUE - timeoutNanos) Long.MAX_VALUE else nowNanos + timeoutNanos
}

internal fun remainingServiceCloseNanos(deadlineNanos: Long): Long {
    val remainingNanos = deadlineNanos - System.nanoTime()
    return if (remainingNanos > 0L) remainingNanos else 0L
}
