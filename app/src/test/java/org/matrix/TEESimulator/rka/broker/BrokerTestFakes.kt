package org.matrix.TEESimulator.rka.broker

import java.util.concurrent.atomic.AtomicBoolean

internal object DirectCallRunner : BrokerCallRunner {
    override fun <T> run(
        service: BrokerServiceKind,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        call: () -> T,
    ): BrokerOutcome<T> {
        if (cancellation.isCancelled()) return BrokerOutcome.Failure(BrokerError.Cancelled)
        if (deadline.hasExpired()) return BrokerOutcome.Failure(BrokerError.DeadlineExceeded)
        return try {
            val value = call()
            brokerTerminalFailure(deadline, cancellation) ?: BrokerOutcome.Success(value)
        } catch (error: Throwable) {
            BrokerFailureMapper.map(service, error)
        }
    }
}

internal class FakeResolver(
    private val irpc: IrpcServiceEndpoint = FakeIrpcEndpoint(),
    private val keyMint: KeyMintServiceEndpoint = FakeKeyMintEndpoint(),
    private val irpcFailure: Throwable? = null,
    private val keyMintFailure: Throwable? = null,
) : BrokerServiceResolver {
    val irpcNames = mutableListOf<String>()
    val keyMintNames = mutableListOf<String>()

    override fun resolveIrpc(name: String): IrpcServiceEndpoint {
        irpcNames += name
        irpcFailure?.let { throw it }
        return irpc
    }

    override fun resolveKeyMint(name: String): KeyMintServiceEndpoint {
        keyMintNames += name
        keyMintFailure?.let { throw it }
        return keyMint
    }
}

internal class FakeIrpcEndpoint(
    override val version: Int = 3,
    override val descriptor: String = IrpcClient.IRPC_DESCRIPTOR,
    override val componentName: String = "TEE",
    override val uniqueId: String = "fake-irpc",
    override val supportedEekCurve: Int = 1,
    override val supportedNumKeysInCsr: Int = 20,
    override val alive: AtomicBoolean = AtomicBoolean(true),
    private val dieOnGenerate: Boolean = false,
    private val onGenerate: (() -> Unit)? = null,
    private val generated: IrpcGeneratedKey =
        IrpcGeneratedKey(byteArrayOf(1, 2, 3), byteArrayOf(9, 8, 7)),
) : IrpcServiceEndpoint {
    override fun generateKey(): IrpcGeneratedKey {
        onGenerate?.invoke()
        if (dieOnGenerate) alive.set(false)
        return generated
    }

    override fun generateCertificateRequestV2(
        keys: List<IrpcGeneratedKey>,
        challenge: ByteArray,
    ): ByteArray = byteArrayOf(0x83.toByte(), keys.size.toByte(), challenge.size.toByte())
}

internal class FakeKeyMintEndpoint(
    override val descriptor: String = KeyMintClient.KEYMINT_DESCRIPTOR,
    override val version: Int = 4,
    override val securityLevel: Int = 1,
    override val implementationName: String = "Fake KeyMint",
    override val authorName: String = "Fake Author",
    override val alive: AtomicBoolean = AtomicBoolean(true),
) : KeyMintServiceEndpoint

internal object MissingBrokerService : NoSuchElementException("missing")
