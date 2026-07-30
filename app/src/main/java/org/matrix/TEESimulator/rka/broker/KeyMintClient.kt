package org.matrix.TEESimulator.rka.broker

import android.hardware.security.keymint.IKeyMintDevice
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.ServiceManager
import java.util.concurrent.atomic.AtomicBoolean

internal interface KeyMintServiceEndpoint {
    val descriptor: String
    val version: Int
    val securityLevel: Int
    val implementationName: String
    val authorName: String
    val alive: AtomicBoolean
}

class KeyMintClient
internal constructor(
    private val resolver: BrokerServiceResolver,
    private val runner: BrokerCallRunner,
) {
    fun capability(
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<KeyMintCapability> {
        val resolved =
            runner.run(BrokerServiceKind.KEYMINT, deadline, cancellation) {
                resolver.resolveKeyMint(DEFAULT_TEE_SERVICE)
            }
        if (resolved is BrokerOutcome.Failure) return resolved
        val endpoint = (resolved as BrokerOutcome.Success).value
        if (!endpoint.alive.get()) {
            return BrokerOutcome.Failure(BrokerError.ServiceDead(BrokerServiceKind.KEYMINT))
        }
        if (
            endpoint.descriptor != KEYMINT_DESCRIPTOR ||
                endpoint.securityLevel != SecurityLevel.TRUSTED_ENVIRONMENT ||
                endpoint.version < 1 ||
                endpoint.implementationName.length !in 1..255 ||
                endpoint.authorName.length !in 1..255
        ) {
            return BrokerOutcome.Failure(
                BrokerError.InvalidBoundary(BrokerError.InvalidBoundary.Boundary.CAPABILITY)
            )
        }
        return BrokerOutcome.Success(
            KeyMintCapability(
                endpoint.descriptor,
                endpoint.version,
                BrokerSecurityLevel.TEE,
                endpoint.implementationName,
                endpoint.authorName,
            )
        )
    }

    companion object {
        const val KEYMINT_DESCRIPTOR = "android.hardware.security.keymint.IKeyMintDevice"
        const val DEFAULT_TEE_SERVICE = "$KEYMINT_DESCRIPTOR/default"
    }
}

internal class AndroidKeyMintServiceEndpoint
private constructor(private val service: IKeyMintDevice, binder: IBinder) : KeyMintServiceEndpoint {
    override val alive = AtomicBoolean(binder.isBinderAlive)
    override val descriptor: String = binder.interfaceDescriptor ?: throw NoSuchElementException()
    private val hardwareInfo = service.hardwareInfo
    override val version: Int = hardwareInfo.versionNumber
    override val securityLevel: Int = hardwareInfo.securityLevel
    override val implementationName: String = hardwareInfo.keyMintName
    override val authorName: String = hardwareInfo.keyMintAuthorName

    init {
        binder.linkToDeath({ alive.set(false) }, 0)
    }

    companion object {
        fun resolve(name: String): AndroidKeyMintServiceEndpoint {
            val binder = ServiceManager.checkService(name) ?: throw NoSuchElementException()
            val service = IKeyMintDevice.Stub.asInterface(binder) ?: throw NoSuchElementException()
            return AndroidKeyMintServiceEndpoint(service, binder)
        }
    }
}
