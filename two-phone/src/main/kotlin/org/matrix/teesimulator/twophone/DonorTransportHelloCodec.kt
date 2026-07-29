package org.matrix.teesimulator.twophone

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

sealed class DonorTransportHelloException(message: String) : RuntimeException(message) {
    class InvalidNonce : DonorTransportHelloException("invalid hello nonce")

    class InvalidLength : DonorTransportHelloException("invalid hello length")

    class InvalidMagic : DonorTransportHelloException("invalid hello magic")

    class UnsupportedVersion : DonorTransportHelloException("unsupported hello version")

    class InvalidFlags : DonorTransportHelloException("invalid hello flags")

    class Truncated : DonorTransportHelloException("truncated hello")

    class TrailingData : DonorTransportHelloException("hello has trailing data")
}

class DonorClientHello(nonce: ByteArray) {
    private val nonceBytes = nonce.validNonce()

    val nonce: ByteArray
        get() = nonceBytes.copyOf()
}

class DonorServerHello(clientNonce: ByteArray, serverNonce: ByteArray) {
    private val clientNonceBytes = clientNonce.validNonce()
    private val serverNonceBytes = serverNonce.validNonce()

    val clientNonce: ByteArray
        get() = clientNonceBytes.copyOf()

    val serverNonce: ByteArray
        get() = serverNonceBytes.copyOf()
}

object DonorTransportHelloCodec {
    private const val CLIENT_BODY_BYTES = 40
    private const val SERVER_BODY_BYTES = 72
    private const val CLIENT_MAGIC = 0x54444348
    private const val SERVER_MAGIC = 0x54445348
    private const val VERSION = 1
    private const val FLAGS = 0

    fun encodeClient(hello: DonorClientHello): ByteArray =
        ByteBuffer.allocate(Int.SIZE_BYTES + CLIENT_BODY_BYTES)
            .putInt(CLIENT_BODY_BYTES)
            .putInt(CLIENT_MAGIC)
            .putShort(VERSION.toShort())
            .putShort(FLAGS.toShort())
            .put(hello.nonce)
            .array()

    fun encodeServer(hello: DonorServerHello): ByteArray =
        ByteBuffer.allocate(Int.SIZE_BYTES + SERVER_BODY_BYTES)
            .putInt(SERVER_BODY_BYTES)
            .putInt(SERVER_MAGIC)
            .putShort(VERSION.toShort())
            .putShort(FLAGS.toShort())
            .put(hello.clientNonce)
            .put(hello.serverNonce)
            .array()

    fun decodeClient(frame: ByteArray): DonorClientHello {
        val reader = validatedReader(frame, CLIENT_BODY_BYTES, CLIENT_MAGIC)
        return DonorClientHello(ByteArray(NONCE_BYTES).also(reader::get))
    }

    fun decodeServer(frame: ByteArray): DonorServerHello {
        val reader = validatedReader(frame, SERVER_BODY_BYTES, SERVER_MAGIC)
        val clientNonce = ByteArray(NONCE_BYTES).also(reader::get)
        return DonorServerHello(clientNonce, ByteArray(NONCE_BYTES).also(reader::get))
    }

    fun readClient(input: InputStream): DonorClientHello? =
        readHello(input, CLIENT_BODY_BYTES, ::decodeClient)

    fun readServer(input: InputStream): DonorServerHello? =
        readHello(input, SERVER_BODY_BYTES, ::decodeServer)

    fun writeClient(output: OutputStream, hello: DonorClientHello) {
        output.write(encodeClient(hello))
        output.flush()
    }

    fun writeServer(output: OutputStream, hello: DonorServerHello) {
        output.write(encodeServer(hello))
        output.flush()
    }

    private fun validatedReader(frame: ByteArray, bodyBytes: Int, magic: Int): ByteBuffer {
        if (frame.size < Int.SIZE_BYTES) throw DonorTransportHelloException.Truncated()
        val declaredBody = ByteBuffer.wrap(frame, 0, Int.SIZE_BYTES).int
        if (declaredBody != bodyBytes) throw DonorTransportHelloException.InvalidLength()
        val totalBytes = Int.SIZE_BYTES + bodyBytes
        if (frame.size < totalBytes) throw DonorTransportHelloException.Truncated()
        if (frame.size > totalBytes) throw DonorTransportHelloException.TrailingData()
        val reader = ByteBuffer.wrap(frame, Int.SIZE_BYTES, bodyBytes)
        if (reader.int != magic) throw DonorTransportHelloException.InvalidMagic()
        if (reader.short.toInt() and 0xffff != VERSION) {
            throw DonorTransportHelloException.UnsupportedVersion()
        }
        if (reader.short.toInt() and 0xffff != FLAGS) {
            throw DonorTransportHelloException.InvalidFlags()
        }
        return reader
    }

    private fun <T> readHello(input: InputStream, bodyBytes: Int, decode: (ByteArray) -> T): T? {
        val prefix = ByteArray(Int.SIZE_BYTES)
        if (
            !readTransportBytes(
                input,
                prefix,
                cleanEofAllowed = true,
                truncated = { DonorTransportHelloException.Truncated() },
            )
        ) {
            return null
        }
        if (ByteBuffer.wrap(prefix).int != bodyBytes) {
            throw DonorTransportHelloException.InvalidLength()
        }
        val frame = ByteArray(Int.SIZE_BYTES + bodyBytes)
        prefix.copyInto(frame)
        readTransportBytes(
            input,
            frame,
            offset = Int.SIZE_BYTES,
            truncated = { DonorTransportHelloException.Truncated() },
        )
        return decode(frame)
    }
}

private const val NONCE_BYTES = 32

private fun ByteArray.validNonce(): ByteArray =
    if (size == NONCE_BYTES) copyOf() else throw DonorTransportHelloException.InvalidNonce()
