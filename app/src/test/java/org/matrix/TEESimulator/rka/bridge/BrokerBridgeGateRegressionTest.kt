package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.util.Comparator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeGateRegressionTest {
    @Test
    fun blocked_read_is_closed_by_the_one_absolute_deadline() {
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val transport = BlockingTransport(release, entered)
        val endpoint = endpoint(transport)
        val outcome = AtomicReference<BridgeResult<BridgeMessage>>()
        val worker = Thread { outcome.set(endpoint.acceptAndDispatch { it }) }

        worker.start()
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        worker.join(500)
        val stillAlive = worker.isAlive
        release.countDown()
        worker.join(1_000)

        assertFalse("blocked read exceeded the absolute five-second deadline", stillAlive)
        assertEquals(BridgeError.DeadlineExceeded, outcome.get().failure())
        assertTrue(transport.closed)
    }

    @Test
    fun blocked_accept_or_connect_is_aborted_inside_the_same_deadline() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val aborts = java.util.concurrent.atomic.AtomicInteger()
        val deferred =
            DeferredBridgeTransport(
                factory = {
                    entered.countDown()
                    release.await()
                    MemoryTransport(byteArrayOf())
                },
                abortPending = {
                    aborts.incrementAndGet()
                    release.countDown()
                },
            )
        val endpoint = endpoint(deferred)
        val started = System.nanoTime()

        val result = endpoint.acceptAndDispatch { it }
        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

        assertTrue(entered.await(1, TimeUnit.SECONDS))
        assertEquals(BridgeError.DeadlineExceeded, result.failure())
        assertTrue("deferred accept/connect took $elapsed ms", elapsed < 1_000)
        assertEquals(1, aborts.get())
    }

    @Test
    fun late_dispatch_result_after_timeout_is_destroyed_and_never_written() {
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(12), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))
        val release = CountDownLatch(1)
        val responseBacking = AtomicReference<ByteArray>()
        val endpoint = endpoint(transport)

        val result =
            endpoint.acceptAndDispatch {
                while (true) {
                    try {
                        release.await()
                        break
                    } catch (_: InterruptedException) {
                        continue
                    }
                }
                val csr = PublicBytes.of(byteArrayOf(9, 9), BridgeLimits.MAX_FRAME_BYTES)
                responseBacking.set(backing(csr))
                BridgeMessage.PublicKeyResponse(it.requestId, csr, listOf(Hash32.of(ByteArray(32))))
            }
        release.countDown()

        assertEquals(BridgeError.DeadlineExceeded, result.failure())
        waitUntil { responseBacking.get()?.all { it == 0.toByte() } == true }
        assertEquals(0, transport.written.size())
        assertEquals(0, endpoint.correlationCountForTest())
    }

    @Test
    fun cancel_interrupts_the_exact_in_flight_worker_and_closes_its_transport() {
        val requestId = RequestId(13)
        val request =
            BridgeMessage.PublicKeyRequest(requestId, PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))
        val entered = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val endpoint = endpoint(transport)
        val outcome = AtomicReference<BridgeResult<BridgeMessage>>()
        val caller = Thread {
            outcome.set(
                endpoint.acceptAndDispatch {
                    entered.countDown()
                    try {
                        CountDownLatch(1).await()
                        error("unreachable")
                    } catch (_: InterruptedException) {
                        interrupted.countDown()
                        throw IllegalStateException("cancelled")
                    }
                }
            )
        }

        caller.start()
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        assertTrue(endpoint.cancel(requestId) is BridgeResult.Success)
        assertTrue(interrupted.await(1, TimeUnit.SECONDS))
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertEquals(BridgeError.Io, outcome.get().failure())
        assertTrue(transport.closed)
        assertEquals(0, endpoint.correlationCountForTest())
        assertEquals(0, transport.written.size())
    }

    @Test
    fun donor_reauthenticates_after_dispatch_before_writing_response() {
        val generation = AtomicLong(4)
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(2), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))
        val endpoint = endpoint(transport, expected = { snapshot(generation.get()) })

        val result =
            endpoint.acceptAndDispatch {
                generation.incrementAndGet()
                BridgeMessage.PublicKeyResponse(
                    it.requestId,
                    PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
                    listOf(Hash32.of(ByteArray(32))),
                )
            }

        assertEquals(BridgeError.PeerIdentityChanged, result.failure())
        assertEquals(0, transport.written.size())
        assertTrue(transport.credentialReads >= 3)
    }

    @Test
    fun donor_rechecks_so_peercred_immediately_before_successful_write() {
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(22), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))

        val result =
            endpoint(transport).acceptAndDispatch {
                BridgeMessage.PublicKeyResponse(
                    it.requestId,
                    PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
                    listOf(Hash32.of(ByteArray(32))),
                )
            }

        assertTrue(result is BridgeResult.Success)
        assertTrue(transport.credentialReads >= 4)
        assertTrue(transport.written.size() > 0)
    }

    @Test
    fun known_tag_in_wrong_direction_and_wrong_matching_response_are_rejected() {
        val resultMessage =
            BridgeMessage.PublicResult(
                RequestId(3),
                NetworkHandle.of(ByteArray(16)),
                PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_CERTIFICATE_BYTES),
                listOf(PublicBytes.of(byteArrayOf(2), BridgeLimits.MAX_CERTIFICATE_BYTES)),
            )
        val wrongDirection =
            BridgeCodec.decode(
                ByteArrayInputStream(
                    BridgeCodec.encode(resultMessage, BridgeDirection.SIDECAR_TO_BROKER)
                ),
                BridgeDirection.SIDECAR_TO_BROKER,
            )
        assertTrue("response-only tag decoded as a request", wrongDirection is BridgeResult.Failure)

        val request =
            BridgeMessage.PublicKeyRequest(RequestId(4), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(
                BridgeCodec.encode(
                    BridgeMessage.Cancel(request.requestId),
                    BridgeDirection.SIDECAR_TO_BROKER,
                )
            )
        val client =
            BrokerBridgeClient(
                expected = { snapshot() },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
            )
        assertTrue(
            "matching request ID released the wrong typed waiter",
            client.exchange(request) is BridgeResult.Failure,
        )
    }

    @Test
    fun candidate_reauthenticates_after_read_before_exposing_response() {
        val generation = AtomicLong(4)
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(24), PublicBytes.of(ByteArray(16), 64), 1)
        val response =
            BridgeMessage.PublicKeyResponse(
                request.requestId,
                PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
                listOf(Hash32.of(ByteArray(32))),
            )
        val transport =
            MemoryTransport(BridgeCodec.encode(response, BridgeExchangeRole.CANDIDATE_RESPONSE))
        val expectedCalls = java.util.concurrent.atomic.AtomicInteger()
        val client =
            BrokerBridgeClient(
                expected = {
                    if (expectedCalls.incrementAndGet() == 2) generation.incrementAndGet()
                    snapshot(generation.get())
                },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
                timeoutMillis = 100,
            )

        val result = client.exchange(request)

        assertEquals(BridgeError.PeerIdentityChanged, result.failure())
        assertEquals(0, client.correlationCountForTest())
        assertTrue(transport.closed)
    }

    @Test
    fun donor_bind_establishes_missing_socket_directory_before_platform_bind() {
        val parent = Files.createTempDirectory("rka-bridge-red")
        val directory = parent.resolve("run").resolve("sockets")
        try {
            runCatching { DonorBridgeServer.bind(directory.resolve("broker.sock")) }
            assertTrue("secure socket directory was never created", Files.isDirectory(directory))
        } finally {
            Files.walk(parent).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun closing_public_bytes_zeroes_the_actual_backing_array() {
        val bytes = PublicBytes.of(byteArrayOf(1, 2, 3, 4), 4)
        val field = PublicBytes::class.java.getDeclaredField("value").apply { isAccessible = true }
        val backing = field.get(bytes) as ByteArray

        (bytes as Any as AutoCloseable).close()

        assertTrue("DTO backing bytes remain live after close", backing.all { it == 0.toByte() })
        assertThrows(IllegalStateException::class.java) { bytes.copyBytes() }
    }

    @Test
    fun nine_maximum_certificates_exceed_the_aggregate_chain_limit() {
        val certificates =
            List(9) {
                PublicBytes.of(
                    ByteArray(BridgeLimits.MAX_CERTIFICATE_BYTES),
                    BridgeLimits.MAX_CERTIFICATE_BYTES,
                )
            }
        assertThrows(IllegalArgumentException::class.java) {
            BridgeMessage.PublicResult(
                RequestId(6),
                NetworkHandle.of(ByteArray(16)),
                PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_CERTIFICATE_BYTES),
                certificates,
            )
        }
        val maximum =
            BridgeMessage.PublicResult(
                RequestId(7),
                NetworkHandle.of(ByteArray(16)),
                PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_CERTIFICATE_BYTES),
                certificates.take(8),
            )
        maximum.close()
        certificates.forEach(PublicBytes::close)
    }

    private fun endpoint(
        transport: BridgeTransport,
        expected: () -> SupervisorSnapshot = { snapshot() },
    ) =
        BrokerBridgeEndpoint(
            expected = expected,
            processIdentity = ProcessIdentitySource { observed() },
            socketMetadata = { SocketMetadata.secureRootOwned() },
            transport = transport,
            timeoutMillis = 100,
        )

    private fun snapshot(generation: Long = 4) =
        SupervisorSnapshot(
            generation,
            0,
            0,
            42,
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            1234,
        )

    private fun observed() =
        ObservedProcessIdentity(
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            1234,
        )

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private fun backing(owner: Any): ByteArray {
        val field = owner.javaClass.getDeclaredField("value")
        field.isAccessible = true
        return field.get(owner) as ByteArray
    }

    private fun waitUntil(predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (!predicate() && System.nanoTime() < deadline) Thread.yield()
        assertTrue(predicate())
    }

    private open class MemoryTransport(bytes: ByteArray) : BridgeTransport {
        private val source = ByteArrayInputStream(bytes)
        val written = ByteArrayOutputStream()
        var closed = false
        var credentialReads = 0

        override fun peerCredentials(): PeerCredentials {
            credentialReads++
            return PeerCredentials(0, 0, 42)
        }

        override fun input(): InputStream = source

        override fun output() = written

        override fun close() {
            closed = true
        }
    }

    private class BlockingTransport(
        private val release: CountDownLatch,
        private val entered: CountDownLatch,
    ) : MemoryTransport(byteArrayOf()) {
        override fun input(): InputStream =
            object : InputStream() {
                override fun read(): Int {
                    entered.countDown()
                    release.await()
                    return -1
                }
            }

        override fun close() {
            super.close()
            release.countDown()
        }
    }
}
