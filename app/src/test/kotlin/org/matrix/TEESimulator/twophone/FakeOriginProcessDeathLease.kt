package org.matrix.TEESimulator.twophone

import java.util.concurrent.atomic.AtomicBoolean
import org.matrix.TEESimulator.interception.core.OriginProcessDeathLease

internal class FakeOriginProcessDeathLease(
    private val triggerDuringClaim: Boolean = false,
    private val claimFailure: RuntimeException? = null,
) : OriginProcessDeathLease {
    private val claimed = AtomicBoolean(false)
    private var onDeath: (() -> Unit)? = null
    private val watchReturned = AtomicBoolean(false)

    val closed = AtomicBoolean(false)
    val watchClosed = AtomicBoolean(false)

    override fun claim(onDeath: () -> Unit): AutoCloseable {
        check(claimed.compareAndSet(false, true))
        this.onDeath = onDeath
        if (triggerDuringClaim) onDeath()
        claimFailure?.let { throw it }
        watchReturned.set(true)
        return AutoCloseable { watchClosed.set(true) }
    }

    override fun close() {
        if (!watchReturned.get()) closed.set(true)
    }

    fun triggerDeath() {
        checkNotNull(onDeath).invoke()
    }
}
