package org.matrix.TEESimulator.rka.bridge

import java.io.InputStream
import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeMaterialLifetimeTest {
    @Test
    fun every_owned_byte_type_zeroes_its_actual_backing_storage() {
        val publicBytes = PublicBytes.of(byteArrayOf(1, 2, 3), 3)
        val hash = Hash32.of(ByteArray(32) { 4 })
        val handle = NetworkHandle.of(ByteArray(16) { 5 })
        val publicBacking = backing(publicBytes)
        val hashBacking = backing(hash)
        val handleBacking = backing(handle)

        publicBytes.close()
        hash.close()
        handle.close()

        assertTrue(publicBacking.all { it == 0.toByte() })
        assertTrue(hashBacking.all { it == 0.toByte() })
        assertTrue(handleBacking.all { it == 0.toByte() })
    }

    @Test
    fun truncated_frame_zeroes_header_and_partial_body_allocations() {
        val bytes =
            BridgeCodec.headerForTest(BridgeDirection.SIDECAR_TO_BROKER, BridgeTag.CANCEL, 1, 4) +
                byteArrayOf(9, 8)
        val input = TrackingInputStream(bytes)

        val result = BridgeCodec.decode(input, BridgeExchangeRole.DONOR_REQUEST)

        assertEquals(BridgeError.Truncated, (result as BridgeResult.Failure).error)
        assertTrue(input.destinations.isNotEmpty())
        assertTrue(input.destinations.all { destination -> destination.all { it == 0.toByte() } })
    }

    @Test
    fun timeout_closes_decoded_request_storage_and_exact_transport() {
        val request =
            BridgeMessage.PublicKeyRequest(
                RequestId(44),
                PublicBytes.of(ByteArray(16) { 7 }, 64),
                1,
            )
        val transport =
            MaterialTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))
        request.close()
        val dispatchEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var decodedBacking: ByteArray? = null
        val endpoint =
            testBrokerBridgeEndpoint(
                expected = { snapshot() },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
                timeoutMillis = 50,
            )

        val result =
            endpoint.acceptAndDispatch {
                decodedBacking = backing((it as BridgeMessage.PublicKeyRequest).challenge)
                dispatchEntered.countDown()
                release.await()
                BridgeMessage.PublicKeyResponse(
                    it.requestId,
                    PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
                    testBatchId(),
                    Hash32.of(ByteArray(32)),
                    testKeyMetadata(Hash32.of(ByteArray(32))),
                )
            }
        release.countDown()

        assertTrue(dispatchEntered.await(1, java.util.concurrent.TimeUnit.SECONDS))
        assertEquals(BridgeError.DeadlineExceeded, (result as BridgeResult.Failure).error)
        assertTrue(transport.closed)
        waitUntil { decodedBacking?.all { it == 0.toByte() } == true }
        assertEquals(0, endpoint.correlationCountForTest())
    }

    private fun backing(owner: Any): ByteArray {
        val field = owner.javaClass.getDeclaredField("value")
        field.isAccessible = true
        return field.get(owner) as ByteArray
    }

    private fun snapshot() =
        SupervisorSnapshot(
            1,
            0,
            0,
            42,
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            123,
        )

    private fun observed() =
        ObservedProcessIdentity(
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            123,
        )

    private fun waitUntil(predicate: () -> Boolean) {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(1)
        while (!predicate() && System.nanoTime() < deadline) Thread.yield()
        assertTrue(predicate())
    }

    private class TrackingInputStream(private val bytes: ByteArray) : InputStream() {
        private var position = 0
        val destinations = mutableListOf<ByteArray>()

        override fun read(): Int =
            if (position < bytes.size) bytes[position++].toInt() and 0xff else -1

        override fun read(destination: ByteArray, offset: Int, length: Int): Int {
            destinations += destination
            if (position >= bytes.size) return -1
            val count = minOf(length, bytes.size - position)
            bytes.copyInto(destination, offset, position, position + count)
            position += count
            return count
        }
    }

    private class MaterialTransport(bytes: ByteArray) : BridgeTransport {
        private val input = java.io.ByteArrayInputStream(bytes)
        var closed = false

        override fun peerCredentials() = PeerCredentials(0, 0, 42)

        override fun input(): InputStream = input

        override fun output() = java.io.ByteArrayOutputStream()

        override fun close() {
            closed = true
        }
    }
}
