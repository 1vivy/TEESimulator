package org.matrix.TEESimulator.rka.broker

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

class BrokerCapability
private constructor(private val irpcClient: IrpcClient, private val keyMintClient: KeyMintClient) {
    fun inspect(
        caller: BrokerCaller,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<BrokerCapabilityReport> {
        if (caller.isSelfCall) return BrokerOutcome.SelfCallBypass
        brokerTerminalFailure(deadline, cancellation)?.let { return it }
        val irpc = irpcClient.capability(deadline, cancellation)
        brokerTerminalFailure(deadline, cancellation)?.let { return it }
        if (irpc is BrokerOutcome.Failure) return irpc
        val keyMint = keyMintClient.capability(deadline, cancellation)
        brokerTerminalFailure(deadline, cancellation)?.let { return it }
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
