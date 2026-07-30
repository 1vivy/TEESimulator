package org.matrix.TEESimulator.rka.bridge

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

interface BridgeExecution {
    fun <T> run(
        timeoutMillis: Long,
        abort: () -> Unit,
        operation: () -> BridgeResult<T>,
    ): BridgeResult<T>
}

internal object InlineBridgeExecution : BridgeExecution {
    override fun <T> run(
        timeoutMillis: Long,
        abort: () -> Unit,
        operation: () -> BridgeResult<T>,
    ): BridgeResult<T> = operation()
}

internal class BoundedBridgeExecution(private val executor: ThreadPoolExecutor = sharedExecutor) :
    BridgeExecution {
    override fun <T> run(
        timeoutMillis: Long,
        abort: () -> Unit,
        operation: () -> BridgeResult<T>,
    ): BridgeResult<T> {
        require(timeoutMillis in 1..BridgeLimits.DEADLINE_MILLIS)
        val started = System.nanoTime()
        val budget = TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val future =
            try {
                executor.submit<BridgeResult<T>>(operation)
            } catch (_: RejectedExecutionException) {
                return BridgeResult.Failure(BridgeError.QueueSaturated)
            }
        return try {
            val elapsed = System.nanoTime() - started
            val remaining = if (elapsed in 0 until budget) budget - elapsed else 0
            if (remaining == 0L) throw TimeoutException()
            val result = future.get(remaining, TimeUnit.NANOSECONDS)
            val terminalElapsed = System.nanoTime() - started
            if (terminalElapsed < 0 || terminalElapsed >= budget) {
                ((result as? BridgeResult.Success<*>)?.value as? AutoCloseable)?.close()
                abort()
                BridgeResult.Failure(BridgeError.DeadlineExceeded)
            } else {
                result
            }
        } catch (_: TimeoutException) {
            future.cancel(true)
            abort()
            executor.purge()
            BridgeResult.Failure(BridgeError.DeadlineExceeded)
        } catch (_: CancellationException) {
            abort()
            BridgeResult.Failure(BridgeError.Cancelled)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            future.cancel(true)
            abort()
            executor.purge()
            BridgeResult.Failure(BridgeError.Cancelled)
        } catch (_: ExecutionException) {
            future.cancel(true)
            abort()
            executor.purge()
            BridgeResult.Failure(BridgeError.Io)
        }
    }

    internal fun activeCount(): Int = executor.activeCount

    internal fun queuedCount(): Int = executor.queue.size

    private companion object {
        val sharedExecutor =
            ThreadPoolExecutor(
                BridgeLimits.MAX_IN_FLIGHT,
                BridgeLimits.MAX_IN_FLIGHT,
                0,
                TimeUnit.MILLISECONDS,
                ArrayBlockingQueue(BridgeLimits.MAX_QUEUED),
                { runnable -> Thread(runnable, "rka-bridge-uds").apply { isDaemon = true } },
                ThreadPoolExecutor.AbortPolicy(),
            )
    }
}
