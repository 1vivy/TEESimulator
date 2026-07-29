package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch

internal sealed interface ForegroundState {
    data object Inactive : ForegroundState

    data class Starting(val attempt: ForegroundAttempt) : ForegroundState

    data object Active : ForegroundState

    data class Stopping(val attempt: ForegroundAttempt, val hadForeground: Boolean) :
        ForegroundState
}

internal sealed interface ForegroundCompletion {
    data object Transitioned : ForegroundCompletion

    data class EntryFailed(val failure: Throwable) : ForegroundCompletion
}

internal class ForegroundAttempt {
    private val finished = CountDownLatch(1)
    @Volatile private var completion: ForegroundCompletion? = null

    fun complete(result: ForegroundCompletion) {
        check(completion == null)
        completion = result
        finished.countDown()
    }

    fun awaitCompletion(): ForegroundCompletion {
        var interrupted = false
        while (finished.count > 0) {
            try {
                finished.await()
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        try {
            return checkNotNull(completion)
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}

internal sealed interface ForegroundStartDecision {
    data object Rejected : ForegroundStartDecision

    data object Ready : ForegroundStartDecision

    data class Start(val attempt: ForegroundAttempt) : ForegroundStartDecision

    data class Wait(val attempt: ForegroundAttempt) : ForegroundStartDecision
}

internal sealed interface ForegroundRemovalDecision {
    data object Cancelled : ForegroundRemovalDecision

    data class Wait(val attempt: ForegroundAttempt) : ForegroundRemovalDecision

    data class Stop(val attempt: ForegroundAttempt, val startId: Int, val hadForeground: Boolean) :
        ForegroundRemovalDecision
}
