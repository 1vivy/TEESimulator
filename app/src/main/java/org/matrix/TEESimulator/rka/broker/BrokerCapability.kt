package org.matrix.TEESimulator.rka.broker

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

enum class BrokerSecurityLevel {
    TEE
}

enum class BrokerEekCurve {
    P256
}

class IrpcCapability
internal constructor(
    val descriptor: String,
    val version: Int,
    val securityLevel: BrokerSecurityLevel,
    val componentName: String,
    val uniqueId: String,
    val supportedEekCurve: BrokerEekCurve,
    val maxCsrKeys: Int,
)

class KeyMintCapability
internal constructor(
    val descriptor: String,
    val version: Int,
    val securityLevel: BrokerSecurityLevel,
    val implementationName: String,
    val authorName: String,
)

class BrokerCapabilityReport
internal constructor(val irpc: IrpcCapability, val keyMint: KeyMintCapability)

class BrokerCaller private constructor(internal val uid: Int, internal val daemonUid: Int) {
    internal val isSelfCall: Boolean
        get() = uid == daemonUid

    companion object {
        fun external(uid: Int, daemonUid: Int): BrokerCaller {
            require(uid >= 0 && daemonUid >= 0)
            return BrokerCaller(uid, daemonUid)
        }
    }
}

class AttestationChallenge private constructor(private val bytes: ByteArray) {
    fun copyBytes(): ByteArray = bytes.copyOf()

    override fun equals(other: Any?): Boolean =
        other is AttestationChallenge && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "AttestationChallenge(length=${bytes.size})"

    companion object {
        const val MIN_BYTES = 16
        const val MAX_BYTES = 64

        fun parse(bytes: ByteArray): BrokerOutcome<AttestationChallenge> =
            if (bytes.size in MIN_BYTES..MAX_BYTES) {
                BrokerOutcome.Success(AttestationChallenge(bytes.copyOf()))
            } else {
                BrokerOutcome.Failure(
                    BrokerError.InvalidBoundary(
                        BrokerError.InvalidBoundary.Boundary.CHALLENGE_LENGTH
                    )
                )
            }
    }
}

class RkpKeyCount private constructor(val value: Int) {
    companion object {
        const val MAX = 20

        fun parse(value: Int): BrokerOutcome<RkpKeyCount> =
            if (value in 1..MAX) {
                BrokerOutcome.Success(RkpKeyCount(value))
            } else {
                BrokerOutcome.Failure(
                    BrokerError.InvalidBoundary(BrokerError.InvalidBoundary.Boundary.KEY_COUNT)
                )
            }
    }
}

internal interface BrokerServiceResolver {
    fun resolveIrpc(name: String): IrpcServiceEndpoint

    fun resolveKeyMint(name: String): KeyMintServiceEndpoint
}

class BrokerDeadline private constructor(internal val timeoutMillis: Long) {
    internal fun hasExpired(): Boolean = timeoutMillis == 0L

    companion object {
        const val MAX_MILLIS = 5_000L

        fun at(timeoutMillis: Long): BrokerDeadline {
            require(timeoutMillis in 0L..MAX_MILLIS)
            return BrokerDeadline(timeoutMillis)
        }
    }
}

class BrokerCancellation private constructor(private val cancelled: AtomicBoolean) {
    fun cancel() {
        cancelled.set(true)
    }

    internal fun isCancelled(): Boolean = cancelled.get()

    companion object {
        fun active(): BrokerCancellation = BrokerCancellation(AtomicBoolean(false))

        fun cancelled(): BrokerCancellation = BrokerCancellation(AtomicBoolean(true))
    }
}

internal interface BrokerCallRunner {
    fun <T> run(
        service: BrokerServiceKind,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        call: () -> T,
    ): BrokerOutcome<T>
}

class BrokerCapability
private constructor(private val irpcClient: IrpcClient, private val keyMintClient: KeyMintClient) {
    fun inspect(
        caller: BrokerCaller,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<BrokerCapabilityReport> {
        if (caller.isSelfCall) return BrokerOutcome.SelfCallBypass
        val irpc = irpcClient.capability(deadline, cancellation)
        if (irpc is BrokerOutcome.Failure) return irpc
        val keyMint = keyMintClient.capability(deadline, cancellation)
        if (keyMint is BrokerOutcome.Failure) return keyMint
        return BrokerOutcome.Success(
            BrokerCapabilityReport(
                (irpc as BrokerOutcome.Success).value,
                (keyMint as BrokerOutcome.Success).value,
            )
        )
    }

    companion object {
        fun android(): BrokerCapability {
            val resolver = AndroidBrokerServiceResolver()
            val runner = ExecutorBrokerCallRunner()
            return BrokerCapability(IrpcClient(resolver, runner), KeyMintClient(resolver, runner))
        }

        internal fun forResolver(
            resolver: BrokerServiceResolver,
            runner: BrokerCallRunner,
        ): BrokerCapability =
            BrokerCapability(IrpcClient(resolver, runner), KeyMintClient(resolver, runner))
    }
}

internal class ExecutorBrokerCallRunner(
    private val executor: ExecutorService =
        ThreadPoolExecutor(
            2,
            2,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(2),
            { runnable -> Thread(runnable, "rka-broker").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
) : BrokerCallRunner {
    override fun <T> run(
        service: BrokerServiceKind,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        call: () -> T,
    ): BrokerOutcome<T> {
        if (cancellation.isCancelled()) return BrokerOutcome.Failure(BrokerError.Cancelled)
        if (deadline.hasExpired()) return BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
        val future =
            try {
                executor.submit<T> { call() }
            } catch (error: RejectedExecutionException) {
                return BrokerFailureMapper.map(service, error)
            }
        val endNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(deadline.timeoutMillis)
        while (true) {
            if (cancellation.isCancelled()) {
                future.cancel(true)
                return BrokerOutcome.Failure(BrokerError.Cancelled)
            }
            val remainingNanos = endNanos - System.nanoTime()
            if (remainingNanos <= 0L) {
                future.cancel(true)
                return BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
            }
            try {
                val pollNanos = minOf(remainingNanos, TimeUnit.MILLISECONDS.toNanos(25))
                val value = future.get(pollNanos, TimeUnit.NANOSECONDS)
                return if (cancellation.isCancelled()) {
                    BrokerOutcome.Failure(BrokerError.Cancelled)
                } else {
                    BrokerOutcome.Success(value)
                }
            } catch (_: TimeoutException) {
                continue
            } catch (error: Throwable) {
                future.cancel(true)
                if (error is InterruptedException) Thread.currentThread().interrupt()
                return BrokerFailureMapper.map(service, error)
            }
        }
    }
}
