package org.matrix.TEESimulator.interception.core

import android.os.Looper
import android.os.MessageQueue
import android.os.ParcelFileDescriptor
import java.util.concurrent.atomic.AtomicBoolean

internal interface OriginProcessDeathLease : AutoCloseable {
    fun claim(onDeath: () -> Unit): AutoCloseable
}

internal class ParcelFileDescriptorOriginProcessDeathLease(
    private val descriptor: ParcelFileDescriptor
) : OriginProcessDeathLease {
    private val claimed = AtomicBoolean(false)

    override fun claim(onDeath: () -> Unit): AutoCloseable {
        check(claimed.compareAndSet(false, true)) { "origin process death lease already claimed" }
        return try {
            PidfdOriginProcessDeathWatch(descriptor, onDeath)
        } catch (failure: RuntimeException) {
            claimed.set(false)
            close()
            throw failure
        }
    }

    override fun close() {
        if (claimed.compareAndSet(false, true)) runCatching(descriptor::close)
    }
}

private class PidfdOriginProcessDeathWatch(
    private val descriptor: ParcelFileDescriptor,
    private val onDeath: () -> Unit,
) : AutoCloseable {
    private val active = AtomicBoolean(true)
    private val queue = checkNotNull(Looper.getMainLooper()).queue
    private val listener =
        MessageQueue.OnFileDescriptorEventListener { _, events ->
            if (
                events and
                    (MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT or
                        MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR) !=
                    0 && active.compareAndSet(true, false)
            ) {
                runCatching(descriptor::close)
                Thread(onDeath, "teesim-origin-death-abort").apply { isDaemon = true }.start()
            }
            0
        }

    init {
        try {
            queue.addOnFileDescriptorEventListener(
                descriptor.fileDescriptor,
                MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT or
                    MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR,
                listener,
            )
        } catch (failure: RuntimeException) {
            active.set(false)
            runCatching(descriptor::close)
            throw failure
        }
    }

    override fun close() {
        if (!active.compareAndSet(true, false)) return
        queue.removeOnFileDescriptorEventListener(descriptor.fileDescriptor)
        runCatching(descriptor::close)
    }
}
