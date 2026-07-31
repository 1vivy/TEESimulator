package org.matrix.TEESimulator.rka.broker

import android.hardware.security.keymint.IRemotelyProvisionedComponent
import android.hardware.security.keymint.MacedPublicKey
import android.os.IBinder
import android.os.ServiceManager
import java.util.concurrent.atomic.AtomicBoolean

class HalCertificateRequest internal constructor(bytes: ByteArray) {
    private val bytes = bytes.copyOf()

    fun copyBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String = "HalCertificateRequest(length=${bytes.size})"
}

internal interface IrpcServiceEndpoint {
    val version: Int
    val descriptor: String
    val componentName: String
    val uniqueId: String
    val supportedEekCurve: Int
    val supportedNumKeysInCsr: Int
    val alive: AtomicBoolean

    fun generateKey(): IrpcGeneratedKey

    fun generateCertificateRequestV2(publicKeys: List<ByteArray>, challenge: ByteArray): ByteArray
}

class IrpcClient
internal constructor(
    private val resolver: BrokerServiceResolver,
    private val runner: BrokerCallRunner,
) {
    fun capability(
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<IrpcCapability> {
        val resolved =
            runner.run(BrokerServiceKind.IRPC, deadline, cancellation) {
                resolver.resolveIrpc(DEFAULT_TEE_SERVICE)
            }
        if (resolved is BrokerOutcome.Failure) return resolved
        val endpoint = (resolved as BrokerOutcome.Success).value
        if (!endpoint.alive.get()) {
            return BrokerOutcome.Failure(BrokerError.ServiceDead(BrokerServiceKind.IRPC))
        }
        if (endpoint.version != REQUIRED_VERSION) {
            return BrokerOutcome.Failure(BrokerError.UnsupportedIrpcVersion(endpoint.version))
        }
        if (
            endpoint.descriptor != IRPC_DESCRIPTOR ||
                endpoint.componentName.length !in 1..255 ||
                endpoint.uniqueId.length !in 1..255 ||
                endpoint.supportedEekCurve != EEK_CURVE_P256 ||
                endpoint.supportedNumKeysInCsr < RkpKeyCount.MAX
        ) {
            return BrokerOutcome.Failure(
                BrokerError.InvalidBoundary(BrokerError.InvalidBoundary.Boundary.CAPABILITY)
            )
        }
        return BrokerOutcome.Success(
            IrpcCapability(
                descriptor = endpoint.descriptor,
                version = endpoint.version,
                securityLevel = BrokerSecurityLevel.TEE,
                componentName = endpoint.componentName,
                uniqueId = endpoint.uniqueId,
                supportedEekCurve = BrokerEekCurve.P256,
                maxCsrKeys = RkpKeyCount.MAX,
            )
        )
    }

    fun generateKeyBatch(
        count: RkpKeyCount,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<IrpcKeyBatch> =
        withV3Endpoint(deadline, cancellation) { endpoint ->
            val keys = List(count.value) { endpoint.generateKey() }
            IrpcKeyBatch(keys)
        }

    fun generateCertificateRequest(
        batch: IrpcKeyBatch,
        challenge: AttestationChallenge,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<HalCertificateRequest> =
        withV3Endpoint(deadline, cancellation) { endpoint ->
            HalCertificateRequest(
                endpoint.generateCertificateRequestV2(batch.publicKeys(), challenge.copyBytes())
            )
        }

    private fun <T> withV3Endpoint(
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        operation: (IrpcServiceEndpoint) -> T,
    ): BrokerOutcome<T> =
        runner.run(BrokerServiceKind.IRPC, deadline, cancellation) {
            val endpoint = resolver.resolveIrpc(DEFAULT_TEE_SERVICE)
            if (!endpoint.alive.get()) throw android.os.DeadObjectException()
            if (endpoint.version != REQUIRED_VERSION) {
                throw UnsupportedIrpcVersionException(endpoint.version)
            }
            val result = operation(endpoint)
            if (!endpoint.alive.get()) throw android.os.DeadObjectException()
            result
        }

    companion object {
        const val IRPC_DESCRIPTOR =
            "android.hardware.security.keymint.IRemotelyProvisionedComponent"
        const val DEFAULT_TEE_SERVICE = "$IRPC_DESCRIPTOR/default"
        const val REQUIRED_VERSION = 3
        private const val EEK_CURVE_P256 = 1
    }
}

internal class AndroidIrpcServiceEndpoint(
    private val service: IRemotelyProvisionedComponent,
    binder: IBinder,
) : IrpcServiceEndpoint {
    private val hardwareInfo = service.hardwareInfo
    override val alive = AtomicBoolean(binder.isBinderAlive)
    override val version: Int = hardwareInfo.versionNumber
    override val descriptor: String = binder.interfaceDescriptor ?: throw NoSuchElementException()
    override val componentName: String = hardwareInfo.rpcAuthorName
    override val uniqueId: String = hardwareInfo.uniqueId
    override val supportedEekCurve: Int = hardwareInfo.supportedEekCurve
    override val supportedNumKeysInCsr: Int = hardwareInfo.supportedNumKeysInCsr

    init {
        binder.linkToDeath({ alive.set(false) }, 0)
    }

    override fun generateKey(): IrpcGeneratedKey {
        val publicKey = MacedPublicKey()
        val blob = service.generateEcdsaP256KeyPair(false, publicKey)
        return IrpcGeneratedKey(publicKey.macedKey, blob)
    }

    override fun generateCertificateRequestV2(
        publicKeys: List<ByteArray>,
        challenge: ByteArray,
    ): ByteArray {
        val macedPublicKeys =
            publicKeys
                .map { key -> MacedPublicKey().apply { macedKey = key.copyOf() } }
                .toTypedArray()
        return service.generateCertificateRequestV2(macedPublicKeys, challenge.copyOf())
    }
}

internal class AndroidBrokerServiceResolver : BrokerServiceResolver {
    override fun resolveIrpc(name: String): IrpcServiceEndpoint {
        val binder = ServiceManager.checkService(name) ?: throw NoSuchElementException()
        val service =
            IRemotelyProvisionedComponent.Stub.asInterface(binder) ?: throw NoSuchElementException()
        return AndroidIrpcServiceEndpoint(service, binder)
    }

    override fun resolveKeyMint(name: String): KeyMintServiceEndpoint =
        AndroidKeyMintServiceEndpoint.resolve(name)
}
