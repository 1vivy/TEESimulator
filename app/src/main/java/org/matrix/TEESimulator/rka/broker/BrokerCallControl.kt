package org.matrix.TEESimulator.rka.broker

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

internal fun interface BrokerMonotonicClock {
    fun nowNanos(): Long
}

private object SystemBrokerMonotonicClock : BrokerMonotonicClock {
    override fun nowNanos(): Long = System.nanoTime()
}

class BrokerDeadline
private constructor(
    internal val expiresAtNanos: Long,
    private val startedAtNanos: Long,
    private val timeoutNanos: Long,
    private val clock: BrokerMonotonicClock,
) {
    internal fun remainingNanos(): Long {
        val nowNanos = clock.nowNanos()
        val elapsedNanos = nowNanos - startedAtNanos
        if (elapsedNanos < 0L || elapsedNanos >= timeoutNanos) return 0L
        val remainingNanos = expiresAtNanos - nowNanos
        return if (remainingNanos in 1L..timeoutNanos) remainingNanos else 0L
    }

    internal fun hasExpired(): Boolean = remainingNanos() == 0L

    companion object {
        const val MAX_MILLIS = 5_000L

        fun at(timeoutMillis: Long): BrokerDeadline =
            at(timeoutMillis, SystemBrokerMonotonicClock)

        internal fun at(
            timeoutMillis: Long,
            clock: BrokerMonotonicClock,
        ): BrokerDeadline {
            require(timeoutMillis in 0L..MAX_MILLIS)
            val startedAtNanos = clock.nowNanos()
            val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            return BrokerDeadline(
                expiresAtNanos = startedAtNanos + timeoutNanos,
                startedAtNanos = startedAtNanos,
                timeoutNanos = timeoutNanos,
                clock = clock,
            )
        }
    }
}

class BrokerCancellation private constructor(private val cancelled: AtomicBoolean) {
    fun cancel() {
        cancelled.set(true)
    }

    internal fun isCancelled(): Boolean = cancelled.get()

    companion object {
        fun active(): BrokerCancellation = BrokerCancellation(AtomicBoolean(false))

        fun cancelled(): BrokerCancellation = BrokerCancellation(AtomicBoolean(true))
    }
}

internal interface BrokerCallRunner {
    fun <T> run(
        service: BrokerServiceKind,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        call: () -> T,
    ): BrokerOutcome<T>
}

internal fun brokerTerminalFailure(
    deadline: BrokerDeadline,
    cancellation: BrokerCancellation,
): BrokerOutcome.Failure? =
    when {
        cancellation.isCancelled() -> BrokerOutcome.Failure(BrokerError.Cancelled)
        deadline.hasExpired() -> BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
        else -> null
    }

internal class ExecutorBrokerCallRunner(
    private val executor: ExecutorService =
        ThreadPoolExecutor(
            2,
            2,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(2),
            { runnable -> Thread(runnable, "rka-broker").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
) : BrokerCallRunner {
    override fun <T> run(
        service: BrokerServiceKind,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        call: () -> T,
    ): BrokerOutcome<T> {
        brokerTerminalFailure(deadline, cancellation)?.let { return it }
        val future =
            try {
                executor.submit<T>(call)
            } catch (error: RejectedExecutionException) {
                return brokerTerminalFailure(deadline, cancellation)
                    ?: BrokerFailureMapper.map(service, error)
            }
        while (true) {
            brokerTerminalFailure(deadline, cancellation)?.let { failure ->
                cancelAndPurge(future)
                return failure
            }
            val remainingNanos = deadline.remainingNanos()
            if (remainingNanos <= 0L) {
                cancelAndPurge(future)
                return BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
            }
            try {
                val pollNanos = minOf(remainingNanos, MAX_POLL_NANOS)
                val value = future.get(pollNanos, TimeUnit.NANOSECONDS)
                return brokerTerminalFailure(deadline, cancellation) ?: BrokerOutcome.Success(value)
            } catch (_: TimeoutException) {
                continue
            } catch (error: Throwable) {
                cancelAndPurge(future)
                if (error is InterruptedException) Thread.currentThread().interrupt()
                return brokerTerminalFailure(deadline, cancellation)
                    ?: BrokerFailureMapper.map(service, error)
            }
        }
    }

    private fun cancelAndPurge(future: Future<*>) {
        future.cancel(true)
        (executor as? ThreadPoolExecutor)?.purge()
    }

    private companion object {
        val MAX_POLL_NANOS: Long = TimeUnit.MILLISECONDS.toNanos(25)
    }
}
