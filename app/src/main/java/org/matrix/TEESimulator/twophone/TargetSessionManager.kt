package org.matrix.TEESimulator.twophone

import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import org.matrix.teesimulator.twophone.AbortRequestPayload
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.FinishRequestPayload
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.PublicProfileLimits
import org.matrix.teesimulator.twophone.TargetPublicProfile
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireOutcome

class TargetSessionManager
private constructor(
    private val profile: TargetPublicProfile,
    private val caller: WireCallerIdentity,
    private val now: () -> Instant,
    private val connectionFactory: TargetConnectionFactory,
) {
    constructor(
        profile: TargetPublicProfile,
        sslContext: SSLContext,
        caller: WireCallerIdentity,
        secureRandom: SecureRandom = SecureRandom(),
        now: () -> Instant = Instant::now,
    ) : this(
        profile,
        caller,
        now,
        JsseTargetConnectionFactory(profile, sslContext, secureRandom, now),
    )

    private val callLock = ReentrantLock()
    private val stateMonitor = Any()
    @Volatile private var connection: TargetConnection? = null
    @Volatile private var closeRequested = false
    @Volatile
    var state = TargetSessionState.DISCONNECTED
        private set

    @Volatile
    var negotiatedProtocol: String? = null
        private set

    private var nextSequence = 0uL
    private val operationCall = ActiveOperationCall()

    init {
        require(profile.maxOperations == PublicProfileLimits.MAX_OPERATIONS)
        require(profile.maxOperations == 1)
        require(profile.deadlineSeconds == PublicProfileLimits.DEADLINE_SECONDS)
        require(profile.deadlineSeconds == 120)
    }

    fun exchange(
        payload: LifecycleRequestPayload,
        deadline: Instant = now().plusSeconds(profile.deadlineSeconds.toLong()),
        cancellation: TargetCallCancellation = TargetCallCancellation(),
    ): WireOutcome = exchange(payload, deadline, cancellation, null)

    internal fun exchangeOwnerDeathAbort(
        payload: AbortRequestPayload,
        deadline: Instant = now().plusSeconds(profile.deadlineSeconds.toLong()),
        cancellation: TargetCallCancellation = TargetCallCancellation(),
    ): WireOutcome = exchange(payload, deadline, cancellation, payload.operation.id)

    private fun exchange(
        payload: LifecycleRequestPayload,
        deadline: Instant,
        cancellation: TargetCallCancellation,
        ownerDeathAbortOperationId: UUID?,
    ): WireOutcome {
        validateDeadline(deadline)
        acquireCall(deadline, cancellation)
        try {
            if (closeRequested) throw TargetSessionException.Closed()
            enforceOperationLimit(payload)
            operationCall.publish(cancellation, ownerDeathAbortOperationId)
            try {
                val active = connection ?: connect(deadline, cancellation)
                val sequence = nextSequence
                nextSequence = increment(sequence)
                return try {
                    active.exchange(sequence, payload, caller, deadline, cancellation).also {
                        updateOperationState(payload, it)
                    }
                } catch (failure: TargetSessionException) {
                    disconnect(active)
                    throw failure
                } catch (failure: RuntimeException) {
                    disconnect(active)
                    throw TargetSessionException.TransportFailure(failure)
                }
            } finally {
                operationCall.clearCall(cancellation)
            }
        } finally {
            callLock.unlock()
        }
    }

    fun cancelActiveOperation(expectedOperationId: UUID): Boolean {
        return operationCall.markOwnerDead(expectedOperationId)
    }

    fun close(): TargetCloseOutcome {
        val active =
            synchronized(stateMonitor) {
                if (state == TargetSessionState.CLOSED) return TargetCloseOutcome.Closed
                closeRequested = true
                state = TargetSessionState.CLOSING
                connection
            }
        if (active == null) {
            synchronized(stateMonitor) { state = TargetSessionState.CLOSED }
            return TargetCloseOutcome.Closed
        }
        return try {
            active.close()
            synchronized(stateMonitor) {
                if (connection === active) connection = null
                negotiatedProtocol = null
                state = TargetSessionState.CLOSED
            }
            TargetCloseOutcome.Closed
        } catch (failure: Throwable) {
            TargetCloseOutcome.Incomplete(failure)
        }
    }

    fun abandonOperation(expectedOperationId: UUID): Boolean {
        callLock.lock()
        try {
            if (!operationCall.clear(expectedOperationId)) return false
            connection?.let(::disconnect)
            return true
        } finally {
            callLock.unlock()
        }
    }

    internal fun discardConnection() {
        callLock.lock()
        try {
            operationCall.clear()
            connection?.let(::disconnect)
        } finally {
            callLock.unlock()
        }
    }

    private fun connect(deadline: Instant, cancellation: TargetCallCancellation): TargetConnection {
        synchronized(stateMonitor) {
            if (closeRequested) throw TargetSessionException.Closed()
            state = TargetSessionState.CONNECTING
        }
        val created =
            try {
                connectionFactory.connect(deadline, cancellation)
            } catch (failure: RuntimeException) {
                synchronized(stateMonitor) {
                    if (!closeRequested) state = TargetSessionState.DISCONNECTED
                }
                throw failure
            }
        synchronized(stateMonitor) {
            if (closeRequested) {
                runCatching(created::close)
                throw TargetSessionException.Closed()
            }
            connection = created
            nextSequence = 0uL
            negotiatedProtocol = created.protocol
            state = TargetSessionState.CONNECTED
            return created
        }
    }

    private fun disconnect(active: TargetConnection) {
        runCatching(active::close)
        synchronized(stateMonitor) {
            if (connection === active) connection = null
            negotiatedProtocol = null
            if (!closeRequested) state = TargetSessionState.DISCONNECTED
        }
    }

    private fun validateDeadline(deadline: Instant) {
        val current = now()
        if (!current.isBefore(deadline)) throw TargetSessionException.DeadlineExceeded()
        if (deadline.isAfter(current.plusSeconds(profile.deadlineSeconds.toLong()))) {
            throw TargetSessionException.InvalidDeadline()
        }
    }

    private fun acquireCall(deadline: Instant, cancellation: TargetCallCancellation) {
        while (true) {
            if (cancellation.isCancelled) throw TargetSessionException.Cancelled()
            val remaining = Duration.between(now(), deadline).toMillis()
            if (remaining <= 0) throw TargetSessionException.DeadlineExceeded()
            try {
                if (callLock.tryLock(remaining.coerceAtMost(50), TimeUnit.MILLISECONDS)) return
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                throw TargetSessionException.Cancelled()
            }
        }
    }

    private fun enforceOperationLimit(payload: LifecycleRequestPayload) {
        if (payload is BeginRequestPayload && operationCall.operationId != null) {
            throw TargetSessionException.OperationLimit()
        }
    }

    private fun updateOperationState(payload: LifecycleRequestPayload, outcome: WireOutcome) {
        val success = outcome as? WireOutcome.Success ?: return
        when (payload) {
            is BeginRequestPayload -> {
                val operationId = (success.payload as? BeginResultPayload)?.operation?.id
                operationCall.begin(operationId)
            }
            is FinishRequestPayload,
            is AbortRequestPayload -> operationCall.complete()
            else -> Unit
        }
    }

    private fun increment(sequence: ULong): ULong {
        if (sequence == ULong.MAX_VALUE) {
            disconnect(
                connection ?: throw TargetSessionException.TransportFailure(ArithmeticException())
            )
            throw TargetSessionException.TransportFailure(ArithmeticException("sequence exhausted"))
        }
        return sequence + 1uL
    }

    internal companion object {
        fun createForTest(
            profile: TargetPublicProfile,
            caller: WireCallerIdentity,
            now: () -> Instant,
            factory: TargetConnectionFactory,
        ) = TargetSessionManager(profile, caller, now, factory)
    }
}
