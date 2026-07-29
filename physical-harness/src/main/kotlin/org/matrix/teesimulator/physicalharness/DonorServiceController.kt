package org.matrix.teesimulator.physicalharness

import java.time.Instant
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService

class DonorServiceController(
    private val runtime: DonorRuntimeControl,
    private val worker: ExecutorService,
    private val callbackExecutor: Executor,
    private val now: () -> Instant,
    private val host: Host,
    private val shutdownTimeoutMillis: Long = DEFAULT_SHUTDOWN_TIMEOUT_MILLIS,
) : AutoCloseable {
    interface Host {
        fun startForegroundNow()

        fun stopSelfIfLatest(startId: Int): Boolean

        fun removeForeground()

        fun terminateDonorProcess(): Nothing
    }

    private val monitor = Any()
    private val submissionLock = Any()
    private val runtimeCalls = DonorRuntimeCallCoordinator(runtime)
    private var acceptingCommands = true
    private var commandVersion = 0L
    private var latestDeliveredStartId = 0
    private var pendingForegroundStarts = 0
    private var foregroundState: ForegroundState = ForegroundState.Inactive
    private var foregroundDesired = false
    private var workerRuntimeDisposition = RuntimeDisposition.CONFIRMED_STOPPED
    private var closeAttempt: DonorServiceCloseAttempt? = null
    private var terminationClaimed = false

    init {
        require(shutdownTimeoutMillis > 0)
    }

    fun handle(command: DonorServiceCommand, startId: Int): Boolean {
        val startsForeground = command is DonorServiceCommand.Start
        synchronized(monitor) {
            latestDeliveredStartId = startId
            if (startsForeground) pendingForegroundStarts += 1
        }
        return try {
            when (command) {
                DonorServiceCommand.Inert -> synchronized(monitor) { acceptingCommands }
                is DonorServiceCommand.Start -> handleValidStart(command)
                DonorServiceCommand.Stop -> handleStop()
            }
        } finally {
            if (startsForeground) synchronized(monitor) { pendingForegroundStarts -= 1 }
        }
    }

    fun handleExplicitStart(profileId: String?, startId: Int): Boolean {
        synchronized(monitor) {
            latestDeliveredStartId = startId
            pendingForegroundStarts += 1
        }
        return try {
            if (!startForegroundIfNeeded()) return false
            val command =
                try {
                    DonorServiceCommand.parse(DonorService.ACTION_START, profileId)
                        as DonorServiceCommand.Start
                } catch (_: DonorServiceCommandException.InvalidStart) {
                    return handleInvalidStart()
                }
            submitStart(command)
        } finally {
            synchronized(monitor) { pendingForegroundStarts -= 1 }
        }
    }

    private fun handleValidStart(command: DonorServiceCommand.Start): Boolean {
        if (!startForegroundIfNeeded()) return false
        return submitStart(command)
    }

    private fun startForegroundIfNeeded(): Boolean {
        while (true) {
            when (val decision = foregroundStartDecision()) {
                ForegroundStartDecision.Rejected -> return false
                ForegroundStartDecision.Ready -> return true
                is ForegroundStartDecision.Start -> return performForegroundStart(decision.attempt)
                is ForegroundStartDecision.Wait ->
                    when (val completion = decision.attempt.awaitCompletion()) {
                        ForegroundCompletion.Transitioned -> Unit
                        is ForegroundCompletion.EntryFailed -> throw completion.failure
                    }
            }
        }
    }

    private fun foregroundStartDecision(): ForegroundStartDecision =
        synchronized(monitor) {
            if (!acceptingCommands) return@synchronized ForegroundStartDecision.Rejected
            when (val state = foregroundState) {
                ForegroundState.Inactive -> {
                    val attempt = ForegroundAttempt()
                    foregroundState = ForegroundState.Starting(attempt)
                    ForegroundStartDecision.Start(attempt)
                }
                ForegroundState.Active -> ForegroundStartDecision.Ready
                is ForegroundState.Starting -> ForegroundStartDecision.Wait(state.attempt)
                is ForegroundState.Stopping -> ForegroundStartDecision.Wait(state.attempt)
            }
        }

    private fun performForegroundStart(attempt: ForegroundAttempt): Boolean {
        val completion =
            try {
                host.startForegroundNow()
                synchronized(monitor) {
                    check(foregroundState == ForegroundState.Starting(attempt))
                    foregroundState = ForegroundState.Active
                }
                ForegroundCompletion.Transitioned
            } catch (failure: Throwable) {
                synchronized(monitor) {
                    check(foregroundState == ForegroundState.Starting(attempt))
                    foregroundState = ForegroundState.Inactive
                }
                ForegroundCompletion.EntryFailed(failure)
            }
        attempt.complete(completion)
        return when (completion) {
            ForegroundCompletion.Transitioned -> true
            is ForegroundCompletion.EntryFailed -> throw completion.failure
        }
    }

    private fun submitStart(command: DonorServiceCommand.Start): Boolean {
        val version =
            synchronized(monitor) {
                if (!acceptingCommands) return@synchronized null
                foregroundDesired = true
                nextCommandVersion()
            } ?: return false
        return submit(version) { runStart(command.profileId, version) }
    }

    private fun handleInvalidStart(): Boolean {
        val version =
            synchronized(monitor) {
                if (!acceptingCommands) return false
                if (foregroundDesired) return true
                foregroundDesired = false
                nextCommandVersion()
            }
        return submit(version, cleanupRejectedSubmission = false) {
            if (workerRuntimeDisposition == RuntimeDisposition.CONFIRMED_STOPPED) {
                scheduleForegroundRemoval(version)
            }
        }
    }

    private fun handleStop(): Boolean {
        val version =
            synchronized(monitor) {
                if (!acceptingCommands) return@synchronized null
                foregroundDesired = false
                nextCommandVersion()
            } ?: return false
        return submit(version) { runStop(version) }
    }

    private fun nextCommandVersion(): Long {
        commandVersion += 1
        return commandVersion
    }

    private fun submit(
        version: Long,
        cleanupRejectedSubmission: Boolean = true,
        task: () -> Unit,
    ): Boolean {
        var executorRejected = false
        val submitted =
            synchronized(submissionLock) {
                if (!synchronized(monitor) { acceptingCommands }) return@synchronized false
                try {
                    worker.execute(task)
                    true
                } catch (_: RuntimeException) {
                    executorRejected = true
                    synchronized(monitor) {
                        acceptingCommands = false
                        foregroundDesired = false
                    }
                    false
                }
            }
        if (executorRejected && cleanupRejectedSubmission) scheduleForegroundRemoval(version)
        return submitted
    }

    private fun runStart(profileId: String, version: Long) {
        workerRuntimeDisposition = RuntimeDisposition.MAY_BE_ACTIVE
        when (val outcome = runtimeCalls.start(profileId, now())) {
            is RuntimeStartCallOutcome.Completed -> Unit
            is RuntimeStartCallOutcome.Failed -> {
                workerRuntimeDisposition = outcome.disposition
                if (outcome.disposition == RuntimeDisposition.CONFIRMED_STOPPED) {
                    scheduleFailedStartRemoval(version)
                }
            }
        }
    }

    private fun runStop(version: Long) {
        when (runtimeCalls.stopUntil(Long.MAX_VALUE)) {
            is RuntimeStopCallOutcome.Confirmed -> {
                workerRuntimeDisposition = RuntimeDisposition.CONFIRMED_STOPPED
                scheduleForegroundRemoval(version)
            }
            is RuntimeStopCallOutcome.Incomplete -> {
                workerRuntimeDisposition = RuntimeDisposition.MAY_BE_ACTIVE
            }
        }
    }

    private fun scheduleFailedStartRemoval(version: Long) {
        val requestIsCurrent =
            synchronized(monitor) {
                if (version != commandVersion) return@synchronized false
                foregroundDesired = false
                true
            }
        if (requestIsCurrent) scheduleForegroundRemoval(version)
    }

    private fun scheduleForegroundRemoval(version: Long) {
        try {
            callbackExecutor.execute { removeForegroundIfCurrent(version) }
        } catch (_: RuntimeException) {
            return
        }
    }

    private fun removeForegroundIfCurrent(version: Long) {
        while (true) {
            when (val decision = foregroundRemovalDecision(version)) {
                ForegroundRemovalDecision.Cancelled -> return
                is ForegroundRemovalDecision.Wait -> {
                    decision.attempt.awaitCompletion()
                }
                is ForegroundRemovalDecision.Stop -> {
                    performForegroundRemoval(version, decision)
                    return
                }
            }
        }
    }

    private fun foregroundRemovalDecision(version: Long): ForegroundRemovalDecision =
        synchronized(monitor) {
            if (version != commandVersion || foregroundDesired) {
                return@synchronized ForegroundRemovalDecision.Cancelled
            }
            when (val state = foregroundState) {
                is ForegroundState.Starting -> ForegroundRemovalDecision.Wait(state.attempt)
                is ForegroundState.Stopping -> ForegroundRemovalDecision.Wait(state.attempt)
                ForegroundState.Active -> claimForegroundStop(hadForeground = true)
                ForegroundState.Inactive -> claimForegroundStop(hadForeground = false)
            }
        }

    private fun claimForegroundStop(hadForeground: Boolean): ForegroundRemovalDecision.Stop {
        val attempt = ForegroundAttempt()
        foregroundState = ForegroundState.Stopping(attempt, hadForeground)
        return ForegroundRemovalDecision.Stop(attempt, latestDeliveredStartId, hadForeground)
    }

    private fun performForegroundRemoval(version: Long, decision: ForegroundRemovalDecision.Stop) {
        val stopped =
            try {
                host.stopSelfIfLatest(decision.startId)
            } catch (_: Throwable) {
                completeForegroundStop(decision, retainedForegroundState(decision))
                return
            }
        if (!stopped) {
            val retryWithNewerId =
                synchronized(monitor) {
                    check(
                        foregroundState ==
                            ForegroundState.Stopping(decision.attempt, decision.hadForeground)
                    )
                    foregroundState = retainedForegroundState(decision)
                    version == commandVersion &&
                        !foregroundDesired &&
                        pendingForegroundStarts == 0 &&
                        latestDeliveredStartId != decision.startId
                }
            decision.attempt.complete(ForegroundCompletion.Transitioned)
            if (retryWithNewerId) scheduleForegroundRemoval(version)
            return
        }

        try {
            host.removeForeground()
        } catch (_: Throwable) {
            completeForegroundStop(decision, retainedForegroundState(decision))
            return
        }
        completeForegroundStop(decision, ForegroundState.Inactive)
    }

    private fun retainedForegroundState(decision: ForegroundRemovalDecision.Stop): ForegroundState =
        if (decision.hadForeground) ForegroundState.Active else ForegroundState.Inactive

    private fun completeForegroundStop(
        decision: ForegroundRemovalDecision.Stop,
        completedState: ForegroundState,
    ) {
        synchronized(monitor) {
            check(
                foregroundState ==
                    ForegroundState.Stopping(decision.attempt, decision.hadForeground)
            )
            foregroundState = completedState
        }
        decision.attempt.complete(ForegroundCompletion.Transitioned)
    }

    fun closeAndReport(): DonorServiceCloseOutcome {
        var ownsAttempt = false
        val attempt =
            synchronized(monitor) {
                closeAttempt?.let {
                    return@synchronized it
                }
                acceptingCommands = false
                commandVersion += 1
                foregroundDesired = false
                DonorServiceCloseAttempt(serviceCloseDeadline(shutdownTimeoutMillis)).also {
                    closeAttempt = it
                    ownsAttempt = true
                }
            }
        if (ownsAttempt) executeCloseAttempt(attempt)
        return attempt.awaitOutcome()
    }

    private fun executeCloseAttempt(attempt: DonorServiceCloseAttempt) {
        var interrupted = false
        try {
            val submitted =
                synchronized(submissionLock) {
                    try {
                        worker.execute { runCloseTask(attempt) }
                        true
                    } catch (_: RuntimeException) {
                        false
                    } finally {
                        worker.shutdown()
                    }
                }
            if (!submitted) {
                attempt.complete(DonorServiceCloseOutcome.INCOMPLETE)
                return
            }

            val graceful = awaitExecutorUntil(worker, attempt.deadlineNanos)
            interrupted = graceful.interrupted
            if (!worker.isTerminated) {
                worker.shutdownNow()
                val forced = awaitExecutorUntil(worker, attempt.deadlineNanos)
                interrupted = interrupted || forced.interrupted
            }
            val closed =
                attempt.runtimeStopConfirmed &&
                    worker.isTerminated &&
                    remainingServiceCloseNanos(attempt.deadlineNanos) > 0L
            attempt.complete(
                if (closed) DonorServiceCloseOutcome.CLOSED else DonorServiceCloseOutcome.INCOMPLETE
            )
        } catch (_: RuntimeException) {
            worker.shutdownNow()
            attempt.complete(DonorServiceCloseOutcome.INCOMPLETE)
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private fun runCloseTask(attempt: DonorServiceCloseAttempt) {
        var outcome = runtimeCalls.stopUntil(attempt.deadlineNanos)
        if (
            outcome is RuntimeStopCallOutcome.Incomplete &&
                remainingServiceCloseNanos(attempt.deadlineNanos) > 0L
        ) {
            outcome = runtimeCalls.stopUntil(attempt.deadlineNanos)
        }
        if (outcome is RuntimeStopCallOutcome.Confirmed) {
            workerRuntimeDisposition = RuntimeDisposition.CONFIRMED_STOPPED
            attempt.confirmRuntimeStopped()
        }
    }

    fun closeOrTerminate() {
        if (closeAndReport() == DonorServiceCloseOutcome.CLOSED) return
        val ownsTermination =
            synchronized(monitor) {
                if (terminationClaimed) return@synchronized false
                terminationClaimed = true
                true
            }
        if (ownsTermination) host.terminateDonorProcess()
    }

    override fun close() = closeOrTerminate()

    private companion object {
        const val DEFAULT_SHUTDOWN_TIMEOUT_MILLIS = 5_000L
    }
}
