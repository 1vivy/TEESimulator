package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import org.matrix.teesimulator.twophone.DonorClientHello
import org.matrix.teesimulator.twophone.DonorServerHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.DonorTransportHelloException

class DonorTransportHelloCodecTest {
    private val clientNonce = ByteArray(32) { it.toByte() }
    private val serverNonce = ByteArray(32) { (it + 32).toByte() }

    @Test
    fun exactGoldenClientAndServerBytes() {
        val client = DonorTransportHelloCodec.encodeClient(DonorClientHello(clientNonce))
        val server =
            DonorTransportHelloCodec.encodeServer(DonorServerHello(clientNonce, serverNonce))

        assertContentEquals(
            ByteBuffer.allocate(44)
                .putInt(40)
                .putInt(0x54444348)
                .putShort(1)
                .putShort(0)
                .put(clientNonce)
                .array(),
            client,
        )
        assertContentEquals(
            ByteBuffer.allocate(76)
                .putInt(72)
                .putInt(0x54445348)
                .putShort(1)
                .putShort(0)
                .put(clientNonce)
                .put(serverNonce)
                .array(),
            server,
        )
    }

    @Test
    fun randomRoundTripsAreDefensive() {
        val random = Random(7)
        repeat(20) {
            val clientBytes = random.nextBytes(32)
            val serverBytes = random.nextBytes(32)
            val client = DonorClientHello(clientBytes)
            val server = DonorServerHello(clientBytes, serverBytes)
            clientBytes.fill(0)
            serverBytes.fill(0)

            val decodedClient =
                DonorTransportHelloCodec.decodeClient(DonorTransportHelloCodec.encodeClient(client))
            val decodedServer =
                DonorTransportHelloCodec.decodeServer(DonorTransportHelloCodec.encodeServer(server))
            assertContentEquals(client.nonce, decodedClient.nonce)
            assertContentEquals(server.clientNonce, decodedServer.clientNonce)
            assertContentEquals(server.serverNonce, decodedServer.serverNonce)
            decodedClient.nonce.fill(0)
            assertContentEquals(client.nonce, decodedClient.nonce)
        }
    }

    @Test
    fun clientDecodeRejectsLengthMagicVersionFlagsTruncationAndTrailing() {
        val valid = DonorTransportHelloCodec.encodeClient(DonorClientHello(clientNonce))
        assertFailsWith<DonorTransportHelloException.InvalidLength> {
            DonorTransportHelloCodec.decodeClient(valid.mutatingInt(0, 39))
        }
        assertFailsWith<DonorTransportHelloException.InvalidMagic> {
            DonorTransportHelloCodec.decodeClient(valid.mutatingInt(4, 0))
        }
        assertFailsWith<DonorTransportHelloException.UnsupportedVersion> {
            DonorTransportHelloCodec.decodeClient(valid.mutatingShort(8, 2))
        }
        assertFailsWith<DonorTransportHelloException.InvalidFlags> {
            DonorTransportHelloCodec.decodeClient(valid.mutatingShort(10, 1))
        }
        assertFailsWith<DonorTransportHelloException.Truncated> {
            DonorTransportHelloCodec.decodeClient(valid.copyOf(valid.size - 1))
        }
        assertFailsWith<DonorTransportHelloException.TrailingData> {
            DonorTransportHelloCodec.decodeClient(valid + 0)
        }
    }

    @Test
    fun serverDecodeRejectsEveryNonCanonicalFrameMutation() {
        val valid =
            DonorTransportHelloCodec.encodeServer(DonorServerHello(clientNonce, serverNonce))
        val invalidFrames =
            listOf(
                DonorTransportHelloException.InvalidLength::class to valid.mutatingInt(0, 71),
                DonorTransportHelloException.InvalidMagic::class to valid.mutatingInt(4, 0),
                DonorTransportHelloException.UnsupportedVersion::class to valid.mutatingShort(8, 2),
                DonorTransportHelloException.InvalidFlags::class to valid.mutatingShort(10, 1),
                DonorTransportHelloException.Truncated::class to valid.copyOf(valid.size - 1),
                DonorTransportHelloException.TrailingData::class to (valid + 0),
            )

        invalidFrames.forEach { (type, frame) ->
            assertFailsWith(type) { DonorTransportHelloCodec.decodeServer(frame) }
        }
        assertFailsWith<DonorTransportHelloException.InvalidNonce> {
            DonorClientHello(ByteArray(31))
        }
    }

    @Test
    fun streamHelpersDistinguishCleanEofAndTruncationAndHandleZeroProgress() {
        val frame = DonorTransportHelloCodec.encodeClient(DonorClientHello(clientNonce))
        assertNull(DonorTransportHelloCodec.readClient(ByteArrayInputStream(ByteArray(0))))
        for (size in 1 until frame.size) {
            assertFailsWith<DonorTransportHelloException.Truncated> {
                DonorTransportHelloCodec.readClient(ByteArrayInputStream(frame.copyOf(size)))
            }
        }

        val decoded = DonorTransportHelloCodec.readClient(ZeroThenShortInputStream(frame))!!
        assertContentEquals(clientNonce, decoded.nonce)
        val output = ByteArrayOutputStream()
        DonorTransportHelloCodec.writeClient(output, decoded)
        assertContentEquals(frame, output.toByteArray())
    }

    private fun ByteArray.mutatingInt(offset: Int, value: Int) =
        copyOf().also { ByteBuffer.wrap(it).putInt(offset, value) }

    private fun ByteArray.mutatingShort(offset: Int, value: Int) =
        copyOf().also { ByteBuffer.wrap(it).putShort(offset, value.toShort()) }
}

internal class ZeroThenShortInputStream(bytes: ByteArray) : InputStream() {
    private val delegate = ByteArrayInputStream(bytes)
    private var returnZero = true

    override fun read(): Int = delegate.read()

    override fun read(target: ByteArray, offset: Int, length: Int): Int {
        if (returnZero) {
            returnZero = false
            return 0
        }
        return delegate.read(target, offset, minOf(3, length))
    }
}
