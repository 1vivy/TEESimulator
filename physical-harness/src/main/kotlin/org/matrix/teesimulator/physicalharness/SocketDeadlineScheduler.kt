package org.matrix.teesimulator.physicalharness

import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal class SocketDeadlineScheduler : AutoCloseable {
    private val executor =
        (Executors.newScheduledThreadPool(1) { task ->
                Thread(task, "donor-transport-deadline").apply { isDaemon = true }
            } as ScheduledThreadPoolExecutor)
            .apply { removeOnCancelPolicy = true }

    fun <T> run(socket: Socket, timeoutMillis: Long, action: () -> T): T {
        val deadline =
            executor.schedule({ closeSocket(socket) }, timeoutMillis, TimeUnit.MILLISECONDS)
        return try {
            action()
        } finally {
            deadline.cancel(false)
        }
    }

    override fun close() {
        val nowNanos = System.nanoTime()
        val timeoutNanos = TimeUnit.SECONDS.toNanos(5)
        val deadlineNanos =
            if (nowNanos > Long.MAX_VALUE - timeoutNanos) Long.MAX_VALUE
            else nowNanos + timeoutNanos
        val result = closeUntil(deadlineNanos)
        if (result.interrupted) Thread.currentThread().interrupt()
    }

    fun closeUntil(deadlineNanos: Long): DeadlineShutdownResult {
        shutdownNow()
        return awaitExecutorUntil(executor, deadlineNanos)
    }

    fun shutdownNow() {
        executor.shutdownNow()
    }

    val isShutdown: Boolean
        get() = executor.isShutdown

    val isTerminated: Boolean
        get() = executor.isTerminated
}

internal fun closeSocket(socket: Socket) {
    try {
        socket.close()
    } catch (_: java.io.IOException) {
        return
    } catch (_: RuntimeException) {
        return
    }
}
