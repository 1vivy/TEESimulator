package org.matrix.TEESimulator.twophone

import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.SSLContext
import org.matrix.teesimulator.physicalharness.DonorSessionDispatcherFactory
import org.matrix.teesimulator.physicalharness.PinnedJsseServerContext
import org.matrix.teesimulator.physicalharness.PinnedMutualTlsDonorServer
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.ProfileEndpoint
import org.matrix.teesimulator.twophone.ProvisionedTargetIdentity
import org.matrix.teesimulator.twophone.PublicProfilePin
import org.matrix.teesimulator.twophone.TargetPublicProfile
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDonorDispatcher

internal class TargetLoopbackTestRig {
    private val pki = TargetTlsTestPki()
    private val address = InetAddress.getLoopbackAddress()
    private val port = ServerSocket(0, 1, address).use(ServerSocket::getLocalPort)
    val donorRoot = pki.root("target-loopback-donor-root")
    val donor = pki.server("target-loopback-donor", donorRoot, address.hostAddress)
    val donorDecoy = pki.server("target-loopback-donor-decoy", donorRoot, address.hostAddress)
    val foreignDonorRoot = pki.root("target-loopback-foreign-donor-root")
    val foreignDonor =
        pki.server("target-loopback-foreign-donor", foreignDonorRoot, address.hostAddress)
    val targetRoot = pki.root("target-loopback-target-root")
    val target = pki.client("target-loopback-target", targetRoot)
    val targetDecoy = pki.client("target-loopback-target-decoy", targetRoot)
    val foreignTargetRoot = pki.root("target-loopback-foreign-target-root")
    val foreignTarget = pki.client("target-loopback-foreign-target", foreignTargetRoot)
    val caller = WireCallerIdentity("loopback-signer", "loopback-application")
    val backends = CopyOnWriteArrayList<TargetLoopbackBackend>()
    private var server: PinnedMutualTlsDonorServer? = null

    val endpointAddress: InetAddress
        get() = address

    val endpointPort: Int
        get() = port

    val profile: TargetPublicProfile = profile(donor, target)

    fun profile(
        donorIdentity: TargetTlsTestIdentity,
        targetIdentity: TargetTlsTestIdentity,
    ): TargetPublicProfile =
        TargetPublicProfile.create(
            FIXTURE_IDENTITY,
            ProfileEndpoint.create(address.address, port),
            listOf(donorIdentity.certificate.encoded, donorIdentity.rootCertificate.encoded),
            PublicProfilePin.fromCertificate(donorIdentity.certificate.encoded),
            ProvisionedTargetIdentity.create(
                AndroidKeyStoreTargetTlsClientIdentity.KEY_ALIAS,
                targetIdentity.certificate.encoded,
                PublicProfilePin.fromCertificate(targetIdentity.certificate.encoded),
            ),
        )

    fun openedIdentity(identity: TargetTlsTestIdentity = target) =
        OpenedTargetTlsClientIdentity(
            AndroidKeyStoreTargetTlsClientIdentity.KEY_ALIAS,
            pki.keyStore(AndroidKeyStoreTargetTlsClientIdentity.KEY_ALIAS, identity),
            TargetTlsTestPki.PASSWORD,
            listOf(identity.certificate.encoded, identity.rootCertificate.encoded),
            SpkiPin.from(identity.certificate),
        )

    fun clientContext(
        profile: TargetPublicProfile = this.profile,
        identity: OpenedTargetTlsClientIdentity = openedIdentity(),
    ): SSLContext = PinnedJsseTargetClientContext.create(identity, profile)

    fun donorServerContext(): SSLContext =
        PinnedJsseServerContext.create(
            pki.keyStore("donor", donor),
            "donor",
            TargetTlsTestPki.PASSWORD,
            SpkiPin.from(donor.certificate),
            pki.trustStore(targetRoot),
        )

    fun manager(
        profile: TargetPublicProfile = this.profile,
        identity: OpenedTargetTlsClientIdentity = openedIdentity(),
    ) = TargetSessionManager(profile, clientContext(profile, identity), caller)

    fun startServer(expectedTarget: TargetTlsTestIdentity = target) {
        check(server == null)
        val context = donorServerContext()
        server =
            PinnedMutualTlsDonorServer(
                    context,
                    address,
                    port,
                    SpkiPin.from(expectedTarget.certificate),
                    SpkiPin.from(donor.certificate),
                    caller,
                    DonorSessionDispatcherFactory { pair, clientNonce, serverNonce, _ ->
                        WireDonorDispatcher.create(pair, clientNonce, serverNonce, Instant::now) {
                            TargetLoopbackBackend(caller).also(backends::add)
                        }
                    },
                    SecureRandom(),
                    Instant::now,
                )
                .also(PinnedMutualTlsDonorServer::start)
    }

    fun stopServer() {
        server?.close()
        server = null
    }

    fun backendInvocations(): Int = backends.sumOf { it.invocations.get() }

    companion object {
        val FIXTURE_IDENTITY =
            FixturePackageIdentity.create(
                "org.matrix.teesimulator.fixture",
                7,
                ByteArray(32) { (it + 1).toByte() },
            )
    }
}
