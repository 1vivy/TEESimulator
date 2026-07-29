package org.matrix.teesimulator.physicalharness

import java.net.InetAddress
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.DonorClientHello
import org.matrix.teesimulator.twophone.DonorServerHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.ImportRequestPayload
import org.matrix.teesimulator.twophone.Method
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.ProtocolVersion
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDonorBackend
import org.matrix.teesimulator.twophone.WireDonorDispatcher
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.matrix.teesimulator.twophone.WireOutcome
import org.matrix.teesimulator.twophone.WireRequestEnvelope

class PinnedMutualTlsDonorServerTest {
    private val caller = WireCallerIdentity("signer", "application")

    @Test
    fun incompleteCloseRetriesUntilEveryShutdownPhaseTerminates() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val rig = ServerTestRig(caller, entered, release)
        rig.server.start()
        rig.openSession(59)

        val first = rig.server.closeUntil(System.nanoTime())

        try {
            assertIs<DonorServerCloseOutcome.Incomplete>(first)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertFalse(rig.server.resourcesClosed)
            assertFalse(rig.server.workersTerminated)
        } finally {
            release.countDown()
        }

        val second = rig.server.closeUntil(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))

        assertEquals(DonorServerCloseOutcome.Closed, second)
        assertTrue(rig.server.resourcesClosed)
        assertTrue(rig.server.acceptorTerminated)
        assertTrue(rig.server.workersTerminated)
        assertTrue(rig.server.deadlineSchedulerTerminated)
        assertEquals(DonorServerCloseOutcome.Closed, rig.server.closeUntil(System.nanoTime()))
    }

    @Test
    fun interruptedCloseFinishesAllPhasesAndRestoresInterruption() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val rig = ServerTestRig(caller, entered, release)
        rig.server.start()
        val socket = rig.openSession(60).first
        var failure: Throwable? = null
        var outcome: DonorServerCloseOutcome? = null
        var restored = false
        val closer = Thread {
            try {
                outcome = rig.server.closeUntil(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))
            } catch (caught: Throwable) {
                failure = caught
            }
            restored = Thread.currentThread().isInterrupted
        }
        closer.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        closer.interrupt()
        release.countDown()
        closer.join(5_000)
        assertEquals(null, failure)
        assertEquals(DonorServerCloseOutcome.Closed, outcome)
        assertTrue(restored)
        assertTrue(rig.server.resourcesClosed)
        assertTrue(rig.server.acceptorTerminated)
        assertTrue(rig.server.workersTerminated)
        assertTrue(rig.server.deadlineSchedulerTerminated)
        assertEquals(1, rig.backends.single().closeCalls.get())
        assertTrue(runCatching { socket.inputStream.read() }.getOrDefault(-1) == -1)
        rig.server.close()
    }

    @Test
    fun realTls13UsesSelectedAliasAndDispatchesMultipleRequests() {
        val rig = ServerTestRig(caller)
        rig.server.start()
        val socket = rig.connect(rig.client)
        assertEquals("TLSv1.3", socket.session.protocol)
        assertTrue(
            SpkiPin.from(
                socket.session.peerCertificates.first() as java.security.cert.X509Certificate
            ) == rig.donorPin
        )
        val clientNonce = testBytes(32, 10)
        DonorTransportHelloCodec.writeClient(socket.outputStream, DonorClientHello(clientNonce))
        val hello = DonorTransportHelloCodec.readServer(socket.inputStream)!!
        assertContentEquals(clientNonce, hello.clientNonce)

        repeat(2) { sequence ->
            val request = rig.request(clientNonce, hello.serverNonce, sequence.toULong())
            BoundedWireFrameIo.write(
                socket.outputStream,
                NormalizedWireCodec.encodeRequest(request),
            )
            val response =
                NormalizedWireCodec.decodeResponse(BoundedWireFrameIo.read(socket.inputStream)!!)
            assertEquals(
                WireErrorCode.UNSUPPORTED_METHOD,
                assertIs<WireOutcome.Error>(response.outcome).code,
            )
        }
        assertEquals(1, rig.factoryCalls.get())
        socket.close()
        rig.server.close()
        assertTrue(rig.backends.single().closed)
    }

    @Test
    fun missingUntrustedAndPkixValidWrongPinClientsAreRejected() {
        val rig = ServerTestRig(caller)
        rig.server.start()
        rig.assertRejected(identity = null)
        rig.assertRejected(rig.untrustedClient)

        val wrongPinServer = rig.server(expectedTarget = SpkiPin.from(rig.otherClient.certificate))
        rig.server.close()
        wrongPinServer.start()
        val socket = rig.connect(rig.client, wrongPinServer.boundPort)
        DonorTransportHelloCodec.writeClient(
            socket.outputStream,
            DonorClientHello(testBytes(32, 11)),
        )
        assertNull(DonorTransportHelloCodec.readServer(socket.inputStream))
        assertEquals(0, rig.factoryCalls.get())
        socket.close()
        wrongPinServer.close()
    }

    @Test
    fun requestLimitClosesBeforeSixtyFifthRequestAndShutdownClosesIdleDispatcher() {
        val rig = ServerTestRig(caller)
        rig.server.start()
        val socket = rig.connect(rig.client)
        val clientNonce = testBytes(32, 12)
        DonorTransportHelloCodec.writeClient(socket.outputStream, DonorClientHello(clientNonce))
        val hello = DonorTransportHelloCodec.readServer(socket.inputStream)!!

        repeat(64) { sequence ->
            val request = rig.request(clientNonce, hello.serverNonce, sequence.toULong())
            BoundedWireFrameIo.write(
                socket.outputStream,
                NormalizedWireCodec.encodeRequest(request),
            )
            assertTrue(BoundedWireFrameIo.read(socket.inputStream) != null)
        }
        assertNull(BoundedWireFrameIo.read(socket.inputStream))
        rig.server.close()
        rig.server.close()
        assertTrue(rig.backends.single().closed)
    }

    @Test
    fun malformedHelloAndOversizedFrameCloseSilently() {
        val rig = ServerTestRig(caller)
        rig.server.start()
        val validHello = DonorTransportHelloCodec.encodeClient(DonorClientHello(testBytes(32, 13)))
        listOf(
                validHello.copyOf().also { java.nio.ByteBuffer.wrap(it).putInt(39) },
                validHello.copyOf().also { it[9] = 2 },
                validHello.copyOf().also { it[11] = 1 },
            )
            .forEach { invalidHello ->
                val malformed = rig.connect(rig.client)
                malformed.outputStream.write(invalidHello)
                malformed.outputStream.flush()
                assertEquals(-1, malformed.inputStream.read())
                malformed.close()
            }
        val truncatedHello = rig.connect(rig.client)
        truncatedHello.outputStream.write(validHello.copyOf(20))
        truncatedHello.outputStream.flush()
        truncatedHello.shutdownOutput()
        assertEquals(-1, truncatedHello.inputStream.read())
        truncatedHello.close()

        val oversized = rig.connect(rig.client)
        DonorTransportHelloCodec.writeClient(
            oversized.outputStream,
            DonorClientHello(testBytes(32, 14)),
        )
        DonorTransportHelloCodec.readServer(oversized.inputStream)
        oversized.outputStream.write(
            java.nio.ByteBuffer.allocate(4).putInt(NormalizedWireCodec.MAX_FRAME_BYTES).array()
        )
        oversized.outputStream.flush()
        assertEquals(-1, oversized.inputStream.read())

        val partial = rig.openSession(15).first
        partial.outputStream.write(
            java.nio.ByteBuffer.allocate(4).putInt(8).array() + byteArrayOf(1, 2)
        )
        partial.outputStream.flush()
        partial.shutdownOutput()
        assertEquals(-1, partial.inputStream.read())
        partial.close()
        rig.server.close()
    }

    @Test
    fun fifthSessionIsRejectedSlotIsReusableAndCloseUnblocksIdleSessions() {
        val rig = ServerTestRig(caller)
        rig.server.start()
        val opened = List(4) { index -> rig.openSession(20 + index) }
        await { rig.server.activeSessionCount == 4 }
        assertFalseSession(rig)

        opened.first().first.close()
        await { rig.server.activeSessionCount < 4 }
        val replacement = rig.openSession(30)
        assertTrue(opened[0].second.serverNonce.contentEquals(opened[1].second.serverNonce).not())

        rig.server.close()
        (opened.drop(1).map { it.first } + replacement.first).forEach { socket ->
            assertTrue(runCatching { socket.inputStream.read() }.getOrDefault(-1) == -1)
            socket.close()
        }
        assertTrue(rig.backends.all { it.closed })
    }

    private fun assertFalseSession(rig: ServerTestRig) {
        val rejected = runCatching { rig.openSession(40) }
        rejected.getOrNull()?.first?.close()
        assertTrue(rejected.isFailure)
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 5_000_000_000L
        while (!condition()) {
            check(System.nanoTime() < deadline)
            Thread.sleep(10)
        }
    }

    private class ServerTestRig(
        private val caller: WireCallerIdentity,
        private val cleanupEntered: CountDownLatch? = null,
        private val releaseCleanup: CountDownLatch? = null,
    ) {
        private val pki = TlsTestPki()
        private val serverRoot = pki.root("server-root")
        private val clientRoot = pki.root("client-root")
        private val untrustedRoot = pki.root("untrusted-root")
        val donor = pki.leaf("donor", serverRoot, server = true)
        private val decoy = pki.leaf("decoy", serverRoot, server = true)
        val client = pki.leaf("client", clientRoot, server = false)
        val otherClient = pki.leaf("other-client", clientRoot, server = false)
        val untrustedClient = pki.leaf("untrusted", untrustedRoot, server = false)
        val donorPin = SpkiPin.from(donor.certificate)
        private val targetPin = SpkiPin.from(client.certificate)
        val factoryCalls = AtomicInteger()
        val backends = CopyOnWriteArrayList<ClosingBackend>()
        val server = server()

        fun server(expectedTarget: SpkiPin = targetPin): PinnedMutualTlsDonorServer {
            val context =
                PinnedJsseServerContext.create(
                    pki.keyStore("donor" to donor, "decoy" to decoy),
                    "donor",
                    TlsTestPki.PASSWORD,
                    donorPin,
                    pki.trustStore(clientRoot),
                )
            return PinnedMutualTlsDonorServer(
                context,
                InetAddress.getLoopbackAddress(),
                0,
                expectedTarget,
                donorPin,
                caller,
                DonorSessionDispatcherFactory { pair, clientNonce, serverNonce, _ ->
                    factoryCalls.incrementAndGet()
                    WireDonorDispatcher.create(pair, clientNonce, serverNonce, Instant::now) {
                        ClosingBackend(cleanupEntered, releaseCleanup).also(backends::add)
                    }
                },
                SecureRandom(),
                Instant::now,
            )
        }

        fun connect(identity: TlsTestIdentity?, port: Int = server.boundPort): SSLSocket {
            val context = pki.clientContext(identity, serverRoot)
            val socket =
                context.socketFactory.createSocket(InetAddress.getLoopbackAddress(), port)
                    as SSLSocket
            socket.enabledProtocols = arrayOf("TLSv1.3")
            socket.soTimeout = 5_000
            socket.startHandshake()
            return socket
        }

        fun assertRejected(identity: TlsTestIdentity?) {
            val socket = runCatching { connect(identity) }.getOrNull() ?: return
            try {
                val write = runCatching {
                    DonorTransportHelloCodec.writeClient(
                        socket.outputStream,
                        DonorClientHello(testBytes(32, 99)),
                    )
                    socket.inputStream.read()
                }
                assertTrue(write.isFailure || write.getOrNull() == -1)
            } finally {
                socket.close()
            }
        }

        fun openSession(seed: Int): Pair<SSLSocket, DonorServerHello> {
            val socket = connect(client)
            DonorTransportHelloCodec.writeClient(
                socket.outputStream,
                DonorClientHello(testBytes(32, seed)),
            )
            return socket to (DonorTransportHelloCodec.readServer(socket.inputStream)!!)
        }

        fun request(clientNonce: ByteArray, serverNonce: ByteArray, sequence: ULong) =
            WireRequestEnvelope(
                ProtocolVersion.V1,
                derivedSessionId(
                    PairIdentity(targetPin.toString(), donorPin.toString()),
                    clientNonce,
                    serverNonce,
                ),
                clientNonce,
                serverNonce,
                sequence,
                UUID.randomUUID(),
                NormalizedWireCodec.payloadHash(ImportRequestPayload),
                Method.IMPORT,
                Instant.now().plusSeconds(20),
                caller,
                ImportRequestPayload,
            )
    }

    private class ClosingBackend(
        private val entered: CountDownLatch? = null,
        private val release: CountDownLatch? = null,
    ) : WireDonorBackend {
        @Volatile var closed = false
        val closeCalls = AtomicInteger()

        override fun generate(command: BackendGenerate): BackendGeneratedKey = error("unused")

        override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
            error("unused")

        override fun delete(command: BackendDelete) = error("unused")

        override fun begin(
            handle: WireKeyHandle,
            spec: WireOperationSpec,
            caller: WireCallerIdentity,
        ): WireOperationHandle = error("unused")

        override fun update(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray = error("unused")

        override fun finish(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray = error("unused")

        override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) =
            error("unused")

        override fun close() {
            closeCalls.incrementAndGet()
            entered?.countDown()
            while (release != null && release.count > 0) {
                try {
                    release.await()
                } catch (_: InterruptedException) {
                    continue
                }
            }
            closed = true
        }
    }
}
