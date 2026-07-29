package org.matrix.teesimulator.physicalharness

import android.content.Context
import java.security.SecureRandom
import java.time.Instant
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireCallerIdentity

fun interface DonorTlsIdentityOpener {
    fun open(expectedDonorPin: SpkiPin, now: Instant): OpenedDonorTlsServerIdentity
}

fun interface DonorCallerResolver {
    fun resolve(): WireCallerIdentity
}

sealed interface DonorServerCloseOutcome {
    data object Closed : DonorServerCloseOutcome

    data class Incomplete(val cause: Throwable? = null) : DonorServerCloseOutcome
}

interface DonorServer : AutoCloseable {
    fun start()

    fun closeUntil(deadlineNanos: Long): DonorServerCloseOutcome

    override fun close() {
        val nowNanos = System.nanoTime()
        val timeoutNanos = 5_000_000_000L
        val deadlineNanos =
            if (nowNanos > Long.MAX_VALUE - timeoutNanos) Long.MAX_VALUE
            else nowNanos + timeoutNanos
        when (val outcome = closeUntil(deadlineNanos)) {
            DonorServerCloseOutcome.Closed -> Unit
            is DonorServerCloseOutcome.Incomplete ->
                throw outcome.cause ?: IllegalStateException("Donor server close did not complete")
        }
    }
}

fun interface PinnedDonorServerFactory<P : Any> {
    fun create(
        profile: DonorProfile,
        identity: OpenedDonorTlsServerIdentity,
        process: P,
        caller: WireCallerIdentity,
    ): DonorServer
}

object AndroidDonorTlsIdentityOpener : DonorTlsIdentityOpener {
    override fun open(expectedDonorPin: SpkiPin, now: Instant): OpenedDonorTlsServerIdentity =
        AndroidKeyStoreDonorTlsServerIdentity.openExisting(expectedDonorPin, now)
}

class AndroidDonorCallerResolver(context: Context) : DonorCallerResolver {
    private val resolver = AndroidOwnCallerIdentityResolver(context)

    override fun resolve(): WireCallerIdentity = resolver.resolve().wireIdentity
}

class AndroidPhysicalDonorProcessFactory(context: Context) :
    PhysicalDonorProcessFactory<PhysicalDonorProcess> {
    private val context = context.applicationContext

    override fun create(): PhysicalDonorProcess {
        val donor = AndroidKeystoreDonor(context)
        val mac = DonorStateSecurityBootstrap(context, donor).bootstrap()
        return PhysicalDonorProcess.create(context, mac, donor)
    }
}

class ProductionPinnedDonorServerFactory(
    private val nonceSource: SecureRandom = SecureRandom(),
    private val now: () -> Instant = Instant::now,
) : PinnedDonorServerFactory<PhysicalDonorProcess> {
    override fun create(
        profile: DonorProfile,
        identity: OpenedDonorTlsServerIdentity,
        process: PhysicalDonorProcess,
        caller: WireCallerIdentity,
    ): DonorServer {
        val password = identity.keyPassword
        val sslContext =
            try {
                PinnedJsseServerContext.create(
                    identity.keyStore,
                    identity.alias,
                    password,
                    profile.expectedDonorPin,
                    DonorTargetTrustStore.create(profile),
                )
            } finally {
                password?.fill('\u0000')
            }
        val dispatcherFactory = PhysicalDonorDispatcherFactory(process, now)
        return PinnedMutualTlsDonorServer(
            sslContext,
            profile.bindAddress,
            profile.port,
            profile.expectedTargetPin,
            profile.expectedDonorPin,
            caller,
            dispatcherFactory,
            nonceSource,
            now,
        )
    }
}
