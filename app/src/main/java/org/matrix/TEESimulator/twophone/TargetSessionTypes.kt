package org.matrix.TEESimulator.twophone

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.matrix.teesimulator.twophone.WireErrorCode

sealed class TargetSessionException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class MissingProfile : TargetSessionException("target public profile is not installed")

    class Closed : TargetSessionException("target session manager is closed")

    class Cancelled : TargetSessionException("target call was cancelled")

    class DeadlineExceeded : TargetSessionException("target call deadline exceeded")

    class InvalidDeadline : TargetSessionException("target call deadline exceeds profile bound")

    class OperationLimit : TargetSessionException("target operation limit reached")

    class IdentityMismatch : TargetSessionException("target session identity or caller mismatch")

    class PeerAuthentication(cause: Throwable? = null) :
        TargetSessionException("donor PKIX or endpoint identity validation failed", cause)

    class DonorPinMismatch(cause: Throwable? = null) :
        TargetSessionException("donor SPKI pin mismatch", cause)

    class TlsProtocol : TargetSessionException("TLS 1.3 was not negotiated")

    class NonceMismatch : TargetSessionException("donor hello nonce mismatch")

    class WrongSession(cause: Throwable? = null) :
        TargetSessionException("response session mismatch", cause)

    class WrongRequestId(cause: Throwable? = null) :
        TargetSessionException("response request id mismatch", cause)

    class ReplayRejected(cause: Throwable? = null) :
        TargetSessionException("replayed response rejected", cause)

    class CorrelationFailure(cause: Throwable) :
        TargetSessionException("response correlation failed", cause)

    class FramingFailure(cause: Throwable) :
        TargetSessionException("bounded transport framing failed", cause)

    class TransportFailure(cause: Throwable) :
        TargetSessionException("remote transport failed without local fallback", cause)

    class RemoteFailure(val code: WireErrorCode) :
        TargetSessionException("donor returned typed failure: $code")
}

enum class TargetSessionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    CLOSING,
    CLOSED,
}

sealed interface TargetCloseOutcome {
    data object Closed : TargetCloseOutcome

    data class Incomplete(val cause: Throwable) : TargetCloseOutcome
}

class TargetCallCancellation {
    private val cancelled = AtomicBoolean(false)
    private val ids = AtomicLong()
    private val monitor = Any()
    private val listeners = mutableMapOf<Long, () -> Unit>()

    val isCancelled: Boolean
        get() = cancelled.get()

    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        val callbacks =
            synchronized(monitor) { listeners.values.toList().also { listeners.clear() } }
        callbacks.forEach { runCatching(it) }
    }

    internal fun onCancel(listener: () -> Unit): AutoCloseable {
        val id = ids.incrementAndGet()
        val invokeNow =
            synchronized(monitor) {
                if (cancelled.get()) true
                else {
                    listeners[id] = listener
                    false
                }
            }
        if (invokeNow) listener()
        return AutoCloseable { synchronized(monitor) { listeners.remove(id) } }
    }
}
