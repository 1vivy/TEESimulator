package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerUdsContractTest {
    @Test
    fun accepts_expected_peer() {
        val fixture = Fixture()
        val request =
            BridgeMessage.PublicKeyRequest(
                requestId = RequestId(7),
                challenge = PublicBytes.of(ByteArray(16) { it.toByte() }, 64),
                keyCount = 1,
            )
        val encoded = BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER)
        val transport = FakeTransport(encoded, fixture.expectedCredentials)
        val endpoint = fixture.endpoint(transport)

        val accepted =
            endpoint.acceptAndDispatch { message ->
                assertEquals(request, message)
                BridgeMessage.PublicKeyResponse(
                    message.requestId,
                    PublicBytes.of(byteArrayOf(0x01, 0x02), BridgeLimits.MAX_FRAME_BYTES),
                    testKeyMetadata(Hash32.of(ByteArray(32) { 0x55 })),
                )
            }

        assertTrue(accepted is BridgeResult.Success)
        val decoded =
            BridgeCodec.decode(
                ByteArrayInputStream(transport.output.toByteArray()),
                BridgeExchangeRole.DONOR_RESPONSE,
            )
        assertTrue(decoded is BridgeResult.Success)
        assertEquals(request.requestId, (decoded as BridgeResult.Success).value.requestId)
        assertEquals(1, fixture.dispatches.get())
    }

    @Test
    fun rejects_pid_start_mismatch() {
        val fixture = Fixture()
        fixture.proc.startTime = 778
        val encoded =
            BridgeCodec.encode(
                BridgeMessage.Cancel(RequestId(1)),
                BridgeDirection.SIDECAR_TO_BROKER,
            )
        val transport = FakeTransport(encoded, fixture.expectedCredentials)

        val result = fixture.endpoint(transport).acceptAndDispatch { error("must not dispatch") }

        assertEquals(BridgeError.PeerIdentityMismatch, (result as BridgeResult.Failure).error)
        assertTrue(transport.closed)
        assertEquals(0, fixture.dispatches.get())
    }

    @Test
    fun rejects_oversize() {
        val header =
            BridgeCodec.headerForTest(
                BridgeDirection.SIDECAR_TO_BROKER,
                BridgeTag.CANCEL,
                1,
                BridgeLimits.MAX_FRAME_BYTES + 1L,
            )
        val fixture = Fixture()
        val transport = FakeTransport(header, fixture.expectedCredentials)

        val result = fixture.endpoint(transport).acceptAndDispatch { error("must not dispatch") }

        assertEquals(BridgeError.FrameTooLarge, (result as BridgeResult.Failure).error)
        assertEquals(0, transport.bodyReadCount)
    }

    @Test
    fun frame_bounds_and_canonical_header_are_enforced_before_body_allocation() {
        val zero =
            BridgeCodec.headerForTest(BridgeDirection.SIDECAR_TO_BROKER, BridgeTag.CANCEL, 1, 0)
        assertEquals(
            BridgeError.EmptyFrame,
            BridgeCodec.decode(ByteArrayInputStream(zero), BridgeDirection.SIDECAR_TO_BROKER)
                .failure(),
        )
        val one =
            BridgeCodec.headerForTest(BridgeDirection.SIDECAR_TO_BROKER, BridgeTag.CANCEL, 1, 1) +
                byteArrayOf(0)
        assertTrue(
            BridgeCodec.decode(ByteArrayInputStream(one), BridgeDirection.SIDECAR_TO_BROKER)
                is BridgeResult.Success
        )
        val maximum =
            BridgeCodec.headerForTest(
                BridgeDirection.SIDECAR_TO_BROKER,
                BridgeTag.CANCEL,
                1,
                BridgeLimits.MAX_FRAME_BYTES.toLong(),
            ) + ByteArray(BridgeLimits.MAX_FRAME_BYTES)
        assertEquals(
            BridgeError.NonCanonical,
            BridgeCodec.decode(ByteArrayInputStream(maximum), BridgeDirection.SIDECAR_TO_BROKER)
                .failure(),
        )
        val unsignedNegative =
            BridgeCodec.headerForTest(
                BridgeDirection.SIDECAR_TO_BROKER,
                BridgeTag.CANCEL,
                1,
                0xffff_ffffL,
            )
        assertEquals(
            BridgeError.FrameTooLarge,
            BridgeCodec.decode(
                    ByteArrayInputStream(unsignedNegative),
                    BridgeDirection.SIDECAR_TO_BROKER,
                )
                .failure(),
        )
        assertEquals(
            BridgeError.Truncated,
            BridgeCodec.decode(
                    ByteArrayInputStream(byteArrayOf(1)),
                    BridgeDirection.SIDECAR_TO_BROKER,
                )
                .failure(),
        )
        assertEquals(
            BridgeError.UnknownTag,
            BridgeCodec.decode(
                    ByteArrayInputStream(
                        BridgeCodec.headerForTest(BridgeDirection.SIDECAR_TO_BROKER, 0x7f, 1, 1) +
                            byteArrayOf(0)
                    ),
                    BridgeDirection.SIDECAR_TO_BROKER,
                )
                .failure(),
        )
        assertEquals(
            BridgeError.ReservedBits,
            BridgeCodec.decode(
                    ByteArrayInputStream(
                        BridgeCodec.headerForTest(
                            BridgeDirection.SIDECAR_TO_BROKER,
                            BridgeTag.CANCEL,
                            1,
                            1,
                            flags = 1,
                        ) + byteArrayOf(0)
                    ),
                    BridgeDirection.SIDECAR_TO_BROKER,
                )
                .failure(),
        )
    }

    @Test
    fun proc_stat_parser_handles_parenthesized_comm_and_rejects_bad_values() {
        assertEquals(
            777L,
            ProcStatParser.startTimeTicks("42 (sidecar (worker)) S ${"0 ".repeat(18)}777 0"),
        )
        assertEquals(null, ProcStatParser.startTimeTicks("42 malformed"))
        assertEquals(
            null,
            ProcStatParser.startTimeTicks("42 (x) S ${"0 ".repeat(18)}18446744073709551616 0"),
        )
        assertEquals(null, ProcStatParser.startTimeTicks("42 (x) S ${"0 ".repeat(18)}-1 0"))
    }

    @Test
    fun identity_rechecked_before_dispatch_blocks_pid_reuse() {
        val fixture = Fixture()
        val encoded =
            BridgeCodec.encode(
                BridgeMessage.Cancel(RequestId(8)),
                BridgeDirection.SIDECAR_TO_BROKER,
            )
        fixture.proc.onRead = { read -> if (read == 2) fixture.proc.startTime++ }

        val result =
            fixture
                .endpoint(FakeTransport(encoded, fixture.expectedCredentials))
                .acceptAndDispatch { error("must not dispatch") }

        assertEquals(BridgeError.PeerIdentityChanged, (result as BridgeResult.Failure).error)
        assertEquals(0, fixture.dispatches.get())
    }

    @Test
    fun root_uid_alone_never_authenticates_and_socket_policy_is_exact() {
        val fixture = Fixture()
        val encoded =
            BridgeCodec.encode(
                BridgeMessage.Cancel(RequestId(9)),
                BridgeDirection.SIDECAR_TO_BROKER,
            )
        val attacker = fixture.expectedCredentials.copy(pid = 999)
        assertEquals(
            BridgeError.PeerIdentityMismatch,
            fixture
                .endpoint(FakeTransport(encoded, attacker))
                .acceptAndDispatch { error("must not dispatch") }
                .failure(),
        )
        for (metadata in
            listOf(
                fixture.socketMetadata.copy(directoryUid = 1),
                fixture.socketMetadata.copy(directoryMode = setOf(PosixFilePermission.OWNER_READ)),
                fixture.socketMetadata.copy(directorySymlink = true),
                fixture.socketMetadata.copy(socketMode = setOf(PosixFilePermission.OWNER_READ)),
            )) {
            assertTrue(SocketPolicy.validate(metadata) is BridgeResult.Failure)
        }
    }

    @Test
    fun selinux_denial_is_typed_and_logs_are_redacted() {
        val fixture = Fixture()
        val encoded =
            BridgeCodec.encode(
                BridgeMessage.Cancel(RequestId(11)),
                BridgeDirection.SIDECAR_TO_BROKER,
            )
        val denied =
            FakeTransport(
                encoded,
                fixture.expectedCredentials,
                credentialError = SecurityException("avc secret-body"),
            )
        val result = fixture.endpoint(denied).acceptAndDispatch { error("must not dispatch") }
        assertEquals(BridgeError.SelinuxDenied, result.failure())
        assertFalse(result.toString().contains("secret-body"))
    }

    @Test
    fun defensive_copy_and_golden_bytes_are_stable() {
        val source = ByteArray(16) { it.toByte() }
        val request =
            BridgeMessage.PublicKeyRequest(
                RequestId(0x0102030405060708L),
                PublicBytes.of(source, 64),
                2,
            )
        source[0] = 99
        val encoded = BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER)
        assertArrayEquals(BRIDGE_GOLDEN_PUBLIC_KEY_REQUEST, encoded)
        val goldenHex =
            requireNotNull(javaClass.getResource("/rka-bridge/public-key-request-v1.hex"))
                .readText()
                .trim()
        assertArrayEquals(goldenHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), encoded)
        val copied = request.challenge.copyBytes()
        copied[0] = 88
        assertEquals(0, request.challenge.copyBytes()[0].toInt())
        assertFalse(request.toString().contains("[B@"))
    }

    @Test
    fun fifth_inflight_and_saturated_queue_fail_closed() {
        val limiter = BridgeCapacity(4)
        val leases = (1..4).map { limiter.acquire().success() }
        assertEquals(BridgeError.Capacity, limiter.acquire().failure())
        leases.forEach { it.close() }
        assertTrue(limiter.acquire() is BridgeResult.Success)

        val queue = BridgeWorkQueue<Int>(4)
        (1..4).forEach { assertTrue(queue.offer(it) is BridgeResult.Success) }
        assertEquals(BridgeError.QueueSaturated, queue.offer(5).failure())
        assertEquals(1, queue.poll())
    }

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private fun <T> BridgeResult<T>.success(): T = (this as BridgeResult.Success).value

    private class Fixture {
        val expectedCredentials = PeerCredentials(uid = 0, gid = 0, pid = 42)
        val proc = FakeProcessIdentity()
        val dispatches = AtomicInteger()
        val socketMetadata = SocketMetadata.secureRootOwned()
        private val snapshot =
            SupervisorSnapshot(
                generation = 3,
                uid = 0,
                gid = 0,
                pid = 42,
                startTimeTicks = 777,
                cmdline = listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
                executablePath = "/data/adb/teesimulator-rka/bin/rka-sidecar",
                executableInode = 1234,
            )

        fun endpoint(transport: FakeTransport): BrokerBridgeEndpoint =
            testBrokerBridgeEndpoint(
                expected = { snapshot },
                processIdentity = proc,
                socketMetadata = { socketMetadata },
                onDispatch = { dispatches.incrementAndGet() },
                transport = transport,
            )
    }

    private class FakeProcessIdentity : ProcessIdentitySource {
        var startTime = 777L
        var reads = 0
        var onRead: (Int) -> Unit = {}

        override fun read(pid: Int): ObservedProcessIdentity {
            reads++
            onRead(reads)
            return ObservedProcessIdentity(
                startTime,
                listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
                "/data/adb/teesimulator-rka/bin/rka-sidecar",
                1234,
            )
        }
    }

    private class FakeTransport(
        input: ByteArray,
        private val credentials: PeerCredentials,
        private val credentialError: Throwable? = null,
    ) : BridgeTransport {
        private val input = ByteArrayInputStream(input)
        val output = ByteArrayOutputStream()
        var closed = false
        var bodyReadCount = 0

        override fun peerCredentials(): PeerCredentials {
            credentialError?.let { throw it }
            return credentials
        }

        override fun input() = input

        override fun output() = output

        override fun noteBodyRead(size: Int) {
            bodyReadCount += size
        }

        override fun close() {
            closed = true
        }
    }
}
