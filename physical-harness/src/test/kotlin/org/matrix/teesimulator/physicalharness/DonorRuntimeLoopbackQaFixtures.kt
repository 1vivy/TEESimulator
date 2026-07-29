package org.matrix.teesimulator.physicalharness

import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.GenerateResultPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireDonorBackend
import org.matrix.teesimulator.twophone.WireDonorDispatcher
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec

internal class DonorRuntimeLoopbackQaRig {
    private val pki = TlsTestPki()
    private val donorRoot = pki.root("loopback-donor-root")
    private val donor = pki.leaf("loopback-donor", donorRoot, server = true)
    private val targetRoot = pki.root("loopback-target-root")
    private val target = pki.leaf("loopback-target", targetRoot, server = false)
    private val loopbackAddress = InetAddress.getLoopbackAddress()
    private val profile =
        DonorProfile.create(
            PROFILE_ID,
            loopbackAddress,
            reserveLoopbackPort(loopbackAddress),
            SpkiPin.from(donor.certificate),
            SpkiPin.from(target.certificate),
            target.certificate.encoded,
            listOf(targetRoot.certificate.encoded),
            now(),
        )
    val donorPin = profile.expectedDonorPin
    val targetPin = profile.expectedTargetPin
    val caller = WireCallerIdentity("loopback-signer", "loopback-application")
    val process = LoopbackQaProcess(caller)
    val processFactoryCalls = AtomicInteger()
    val serverFactory = LoopbackQaPinnedServerFactory()
    val owner =
        DonorRuntimeOwner(
            InMemoryDonorConfigSource(listOf(profile)),
            identityOpener(),
            DonorProcessHolder(),
            PhysicalDonorProcessFactory {
                processFactoryCalls.incrementAndGet()
                process
            },
            DonorCallerResolver { caller },
            serverFactory,
        )

    fun now(): Instant = Instant.now()

    fun connect(): SSLSocket {
        val context = pki.clientContext(target, donorRoot)
        return (context.socketFactory.createSocket(profile.bindAddress, profile.port) as SSLSocket)
            .apply {
                enabledProtocols = arrayOf("TLSv1.3")
                soTimeout = 5_000
                startHandshake()
            }
    }

    fun assertDeterministicResult(result: GenerateResultPayload) {
        assertEquals(GENERATION_ID, result.generationId)
        assertEquals(KEY_ID, result.handle.id)
        assertContentEquals(HANDLE_BINDING, result.handle.binding)
        assertEquals(KeyState.ACTIVE, result.metadata.state)
        assertContentEquals(CHALLENGE, result.metadata.attestationChallenge)
        assertContentEquals(PUBLIC_KEY, result.metadata.publicKey)
        assertEquals(1, result.metadata.certificateChain.size)
        assertContentEquals(CERTIFICATE, result.metadata.certificateChain.single())
        assertEquals(KEY_SPEC, result.metadata.keySpec)
    }

    private fun identityOpener(): DonorTlsIdentityOpener {
        val identity =
            OpenedDonorTlsServerIdentity(
                "loopback-donor",
                pki.keyStore("loopback-donor" to donor),
                TlsTestPki.PASSWORD,
                listOf(donor.certificate.encoded, donorRoot.certificate.encoded),
                donorPin,
            )
        return DonorTlsIdentityOpener { expectedPin, _ ->
            require(expectedPin == donorPin)
            identity
        }
    }

    companion object {
        const val PROFILE_ID = "loopback.qa"
        val GENERATION_ID: UUID = UUID.fromString("20000000-0000-0000-0000-000000000001")
        val KEY_ID: UUID = UUID.fromString("20000000-0000-0000-0000-000000000002")
        val LOGICAL_NAME_HASH = ByteArray(32) { index -> (0x20 + index).toByte() }
        val CHALLENGE = byteArrayOf(9, 8, 7, 6)
        val HANDLE_BINDING = ByteArray(32) { index -> (0x40 + index).toByte() }
        val PUBLIC_KEY = byteArrayOf(1, 3, 5, 7, 9)
        val CERTIFICATE = byteArrayOf(2, 4, 6, 8)
        val KEY_SPEC =
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            )

        private fun reserveLoopbackPort(address: InetAddress): Int =
            ServerSocket(0, 1, address).use(ServerSocket::getLocalPort)
    }
}

internal class LoopbackQaProcess(private val expectedCaller: WireCallerIdentity) {
    val backends = CopyOnWriteArrayList<LoopbackQaBackend>()

    fun newBackend(): LoopbackQaBackend = LoopbackQaBackend(expectedCaller).also(backends::add)
}

internal class LoopbackQaPinnedServerFactory : PinnedDonorServerFactory<LoopbackQaProcess> {
    lateinit var server: PinnedMutualTlsDonorServer
        private set

    override fun create(
        profile: DonorProfile,
        identity: OpenedDonorTlsServerIdentity,
        process: LoopbackQaProcess,
        caller: WireCallerIdentity,
    ): DonorServer {
        val password = identity.keyPassword
        val context =
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
        val dispatcherFactory =
            DonorSessionDispatcherFactory { pair, clientNonce, serverNonce, expectedCaller ->
                require(expectedCaller == caller)
                WireDonorDispatcher.create(pair, clientNonce, serverNonce, Instant::now) {
                    process.newBackend()
                }
            }
        return PinnedMutualTlsDonorServer(
                context,
                profile.bindAddress,
                profile.port,
                profile.expectedTargetPin,
                profile.expectedDonorPin,
                caller,
                dispatcherFactory,
                SecureRandom(),
                Instant::now,
            )
            .also { server = it }
    }
}

internal class LoopbackQaBackend(private val expectedCaller: WireCallerIdentity) :
    WireDonorBackend {
    val generateCalls = AtomicInteger()
    val closeCalls = AtomicInteger()

    override fun generate(command: BackendGenerate): BackendGeneratedKey {
        require(command.caller == expectedCaller)
        require(command.keySpec == DonorRuntimeLoopbackQaRig.KEY_SPEC)
        generateCalls.incrementAndGet()
        return BackendGeneratedKey(
            WireKeyHandle(
                DonorRuntimeLoopbackQaRig.KEY_ID,
                DonorRuntimeLoopbackQaRig.HANDLE_BINDING,
            ),
            WireKeyMetadata(
                KeyState.ACTIVE,
                command.challenge,
                DonorRuntimeLoopbackQaRig.PUBLIC_KEY,
                listOf(DonorRuntimeLoopbackQaRig.CERTIFICATE),
                command.keySpec,
            ),
        )
    }

    override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
        error("unexpected loopback QA metadata call")

    override fun delete(command: BackendDelete) = error("unexpected loopback QA delete call")

    override fun begin(
        handle: WireKeyHandle,
        spec: WireOperationSpec,
        caller: WireCallerIdentity,
    ): WireOperationHandle = error("unexpected loopback QA begin call")

    override fun update(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray = error("unexpected loopback QA update call")

    override fun finish(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray = error("unexpected loopback QA finish call")

    override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) =
        error("unexpected loopback QA abort call")

    override fun close() {
        closeCalls.incrementAndGet()
    }
}
