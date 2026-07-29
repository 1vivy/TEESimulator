package org.matrix.teesimulator.physicalharness

import java.time.Instant
import java.util.concurrent.locks.ReentrantLock

internal enum class RuntimeDisposition {
    CONFIRMED_STOPPED,
    MAY_BE_ACTIVE,
}

internal sealed interface RuntimeStartCallOutcome {
    data class Completed(val result: DonorRuntimeStartResult) : RuntimeStartCallOutcome

    data class Failed(val failure: Throwable, val disposition: RuntimeDisposition) :
        RuntimeStartCallOutcome
}

internal sealed interface RuntimeStopCallOutcome {
    data class Confirmed(val result: DonorRuntimeStopResult) : RuntimeStopCallOutcome

    data class Incomplete(val failure: Throwable) : RuntimeStopCallOutcome
}

internal class DonorRuntimeCallCoordinator(private val runtime: DonorRuntimeControl) {
    private val callLock = ReentrantLock()

    fun start(profileId: String, now: Instant): RuntimeStartCallOutcome = withRuntimeCall {
        try {
            RuntimeStartCallOutcome.Completed(runtime.start(profileId, now))
        } catch (failure: Throwable) {
            val disposition =
                try {
                    if (runtime.state == DonorRuntimeState.STOPPED) {
                        RuntimeDisposition.CONFIRMED_STOPPED
                    } else {
                        RuntimeDisposition.MAY_BE_ACTIVE
                    }
                } catch (_: Throwable) {
                    RuntimeDisposition.MAY_BE_ACTIVE
                }
            RuntimeStartCallOutcome.Failed(failure, disposition)
        }
    }

    fun stopUntil(deadlineNanos: Long): RuntimeStopCallOutcome = withRuntimeCall {
        stopUntilWithoutLock(deadlineNanos)
    }

    private inline fun <T> withRuntimeCall(block: () -> T): T {
        callLock.lock()
        return try {
            block()
        } finally {
            callLock.unlock()
        }
    }

    private fun stopUntilWithoutLock(deadlineNanos: Long): RuntimeStopCallOutcome =
        try {
            RuntimeStopCallOutcome.Confirmed(runtime.stopUntil(deadlineNanos))
        } catch (failure: Throwable) {
            RuntimeStopCallOutcome.Incomplete(failure)
        }
}
