package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

class DonorRuntimeCallCoordinatorTest {
    private val now = Instant.parse("2026-01-02T03:04:05Z")

    @Test
    fun startReturnsCompletedOrFailedWithTruthfulDisposition() {
        val completedRuntime = OutcomeRuntime()
        assertEquals(
            RuntimeStartCallOutcome.Completed(DonorRuntimeStartResult.STARTED),
            DonorRuntimeCallCoordinator(completedRuntime).start("approved.profile", now),
        )

        val stoppedFailure = TestServiceFailure()
        val stoppedRuntime = OutcomeRuntime(startFailure = stoppedFailure)
        val stopped =
            assertIs<RuntimeStartCallOutcome.Failed>(
                DonorRuntimeCallCoordinator(stoppedRuntime).start("approved.profile", now)
            )
        assertSame(stoppedFailure, stopped.failure)
        assertEquals(RuntimeDisposition.CONFIRMED_STOPPED, stopped.disposition)

        val activeFailure = TestServiceFailure()
        val activeRuntime =
            OutcomeRuntime(runtimeState = DonorRuntimeState.RUNNING, startFailure = activeFailure)
        val active =
            assertIs<RuntimeStartCallOutcome.Failed>(
                DonorRuntimeCallCoordinator(activeRuntime).start("approved.profile", now)
            )
        assertSame(activeFailure, active.failure)
        assertEquals(RuntimeDisposition.MAY_BE_ACTIVE, active.disposition)
    }

    @Test
    fun startStateReadFailureIsConservativelyMaybeActive() {
        val failure = TestServiceFailure()
        val runtime = OutcomeRuntime(startFailure = failure, stateFailure = TestServiceFailure())

        val outcome =
            assertIs<RuntimeStartCallOutcome.Failed>(
                DonorRuntimeCallCoordinator(runtime).start("approved.profile", now)
            )

        assertSame(failure, outcome.failure)
        assertEquals(RuntimeDisposition.MAY_BE_ACTIVE, outcome.disposition)
    }

    @Test
    fun stopUntilReturnsConfirmedOrIncompleteAndForwardsDeadline() {
        val deadline = 123_456_789L
        val completedRuntime = OutcomeRuntime(runtimeState = DonorRuntimeState.RUNNING)
        assertEquals(
            RuntimeStopCallOutcome.Confirmed(DonorRuntimeStopResult.STOPPED),
            DonorRuntimeCallCoordinator(completedRuntime).stopUntil(deadline),
        )
        assertEquals(deadline, completedRuntime.stopDeadlineNanos)

        val failure = TestServiceFailure()
        val failedRuntime =
            OutcomeRuntime(runtimeState = DonorRuntimeState.RUNNING, stopFailure = failure)
        val incomplete =
            assertIs<RuntimeStopCallOutcome.Incomplete>(
                DonorRuntimeCallCoordinator(failedRuntime).stopUntil(deadline)
            )
        assertSame(failure, incomplete.failure)
    }

    @Test
    fun successfulStopDoesNotReadRuntimeState() {
        val runtime =
            OutcomeRuntime(
                runtimeState = DonorRuntimeState.RUNNING,
                stateFailure = TestServiceFailure(),
            )

        val outcome = DonorRuntimeCallCoordinator(runtime).stopUntil(987_654_321L)

        assertEquals(RuntimeStopCallOutcome.Confirmed(DonorRuntimeStopResult.STOPPED), outcome)
    }
}

private class OutcomeRuntime(
    private var runtimeState: DonorRuntimeState = DonorRuntimeState.STOPPED,
    private val startFailure: RuntimeException? = null,
    private val stopFailure: RuntimeException? = null,
    private val stateFailure: RuntimeException? = null,
) : DonorRuntimeControl {
    var stopDeadlineNanos: Long? = null

    override val state: DonorRuntimeState
        get() {
            stateFailure?.let { throw it }
            return runtimeState
        }

    override fun start(profileId: String, now: Instant): DonorRuntimeStartResult {
        startFailure?.let { throw it }
        runtimeState = DonorRuntimeState.RUNNING
        return DonorRuntimeStartResult.STARTED
    }

    override fun stop(): DonorRuntimeStopResult = stopUntil(Long.MAX_VALUE)

    override fun stopUntil(deadlineNanos: Long): DonorRuntimeStopResult {
        stopDeadlineNanos = deadlineNanos
        stopFailure?.let { throw it }
        runtimeState = DonorRuntimeState.STOPPED
        return DonorRuntimeStopResult.STOPPED
    }
}
