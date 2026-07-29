package org.matrix.teesimulator.physicalharness

import java.security.KeyStore
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireCallerIdentity

internal class DonorRuntimeTestRig(
    profiles: Collection<DonorProfile> = listOf(DonorProfileFixture().profile()),
    processHolder: DonorProcessHolder<TestDonorProcess> = DonorProcessHolder(),
) {
    val source = InMemoryDonorConfigSource(profiles)
    val identity = testOpenedIdentity()
    val identityCalls = AtomicInteger()
    var identityFailure: RuntimeException? = null
    val identityOpener = DonorTlsIdentityOpener { _, _ ->
        identityCalls.incrementAndGet()
        identityFailure?.let { throw it }
        identity
    }
    val process = TestDonorProcess()
    val processCalls = AtomicInteger()
    var processFailure: RuntimeException? = null
    val processFactory =
        PhysicalDonorProcessFactory<TestDonorProcess> {
            processCalls.incrementAndGet()
            processFailure?.let { throw it }
            process
        }
    val caller = WireCallerIdentity("signer", "application")
    val callerCalls = AtomicInteger()
    var callerFailure: RuntimeException? = null
    val callerResolver = DonorCallerResolver {
        callerCalls.incrementAndGet()
        callerFailure?.let { throw it }
        caller
    }
    val serverFactory = FakePinnedDonorServerFactory()
    val holder = processHolder
    val owner =
        DonorRuntimeOwner(
            source,
            identityOpener,
            holder,
            processFactory,
            callerResolver,
            serverFactory,
        )
}

internal class InMemoryDonorConfigSource(profiles: Collection<DonorProfile>) : DonorConfigSource {
    private val profilesById = profiles.associateBy(DonorProfile::profileId).toMap()
    val calls = AtomicInteger()

    override fun load(profileId: String, now: Instant): DonorProfile? {
        DonorProfile.requireValidProfileId(profileId)
        calls.incrementAndGet()
        return profilesById[profileId]
    }
}

internal class FakePinnedDonorServerFactory : PinnedDonorServerFactory<TestDonorProcess> {
    val createCalls = AtomicInteger()
    val servers = CopyOnWriteArrayList<FakeDonorServer>()
    var createFailure: RuntimeException? = null
    var nextStartFailure: RuntimeException? = null
    var nextCloseOutcomes: List<DonorServerCloseOutcome> = emptyList()
    var startEntered: CountDownLatch? = null
    var releaseStart: CountDownLatch? = null

    override fun create(
        profile: DonorProfile,
        identity: OpenedDonorTlsServerIdentity,
        process: TestDonorProcess,
        caller: WireCallerIdentity,
    ): DonorServer {
        createCalls.incrementAndGet()
        createFailure?.let { throw it }
        return FakeDonorServer(nextStartFailure, startEntered, releaseStart).also {
            it.closeOutcomes += nextCloseOutcomes
            nextStartFailure = null
            nextCloseOutcomes = emptyList()
            servers += it
        }
    }
}

internal class FakeDonorServer(
    private val startFailure: RuntimeException?,
    private val startEntered: CountDownLatch?,
    private val releaseStart: CountDownLatch?,
) : DonorServer {
    val closeOutcomes = ArrayDeque<DonorServerCloseOutcome>()
    val startCalls = AtomicInteger()
    val closeCalls = AtomicInteger()
    val closeDeadlines = CopyOnWriteArrayList<Long>()

    override fun start() {
        startCalls.incrementAndGet()
        startEntered?.countDown()
        releaseStart?.await()
        startFailure?.let { throw it }
    }

    override fun closeUntil(deadlineNanos: Long): DonorServerCloseOutcome {
        closeCalls.incrementAndGet()
        closeDeadlines += deadlineNanos
        return closeOutcomes.removeFirstOrNull() ?: DonorServerCloseOutcome.Closed
    }
}

private fun testOpenedIdentity(): OpenedDonorTlsServerIdentity {
    val fixture = DonorProfileFixture()
    val keyStore = KeyStore.getInstance("PKCS12").apply { load(null, null) }
    return OpenedDonorTlsServerIdentity(
        alias = "test",
        keyStore = keyStore,
        keyPassword = null,
        certificateChainDer = listOf(fixture.donor.certificate.encoded),
        pin = SpkiPin.from(fixture.donor.certificate),
    )
}
