package org.matrix.teesimulator.twophone

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.DateTimeException
import java.time.Instant
import java.util.UUID

sealed class WireCodecException(message: String) : RuntimeException(message) {
    class MalformedFrame : WireCodecException("malformed normalized frame")

    class TruncatedFrame : WireCodecException("truncated normalized frame")

    class TrailingData : WireCodecException("normalized frame has trailing data")

    class UnknownVersion(val tag: Int) : WireCodecException("unknown protocol version: $tag")

    class UnknownFrameType(val tag: Int) : WireCodecException("unknown frame type: $tag")

    class UnknownMethod(val tag: Int) : WireCodecException("unknown method: $tag")

    class UnknownPayloadType(val tag: Int) : WireCodecException("unknown payload type: $tag")

    class UnknownOutcomeType(val tag: Int) : WireCodecException("unknown outcome type: $tag")

    class UnknownErrorCode(val tag: Int) : WireCodecException("unknown error code: $tag")

    class UnknownKeyState(val tag: Int) : WireCodecException("unknown key state: $tag")

    class UnknownSpecTag(val field: String, val tag: Int) :
        WireCodecException("unknown $field tag: $tag")

    class InvalidLength(val field: String) : WireCodecException("invalid length for $field")

    class InvalidUtf8(val field: String) : WireCodecException("invalid UTF-8 for $field")

    class OversizedFrame : WireCodecException("normalized frame exceeds 2 MiB")

    class MethodPayloadMismatch : WireCodecException("method and typed payload do not match")

    class PayloadHashMismatch : WireCodecException("typed payload hash mismatch")
}

internal fun frameReader(frame: ByteArray): WireReader {
    if (frame.size > NormalizedWireCodec.MAX_FRAME_BYTES) throw WireCodecException.OversizedFrame()
    if (frame.size < Int.SIZE_BYTES) throw WireCodecException.TruncatedFrame()
    val declaredSize = ByteBuffer.wrap(frame, 0, Int.SIZE_BYTES).int
    if (declaredSize < 0) throw WireCodecException.InvalidLength("frame")
    if (declaredSize > NormalizedWireCodec.MAX_FRAME_BYTES - Int.SIZE_BYTES) {
        throw WireCodecException.OversizedFrame()
    }
    val actualSize = frame.size - Int.SIZE_BYTES
    if (actualSize < declaredSize) throw WireCodecException.TruncatedFrame()
    if (actualSize > declaredSize) throw WireCodecException.TrailingData()
    return WireReader(frame, Int.SIZE_BYTES)
}

internal class WireWriter {
    private val bytes = ByteArrayOutputStream()
    private val output = DataOutputStream(bytes)

    fun writeByte(value: Int) = output.writeByte(value)

    fun writeUnsignedShort(value: Int) {
        if (value !in 0..0xffff) throw WireCodecException.MalformedFrame()
        output.writeShort(value)
    }

    fun writeInt(value: Int) = output.writeInt(value)

    fun writeULong(value: ULong) = output.writeLong(value.toLong())

    fun writeUuid(value: UUID) {
        output.writeLong(value.mostSignificantBits)
        output.writeLong(value.leastSignificantBits)
    }

    fun writeInstant(value: Instant) {
        output.writeLong(value.epochSecond)
        output.writeInt(value.nano)
    }

    fun writeFixed(field: String, value: ByteArray, expectedSize: Int) {
        if (value.size != expectedSize) throw WireCodecException.InvalidLength(field)
        output.write(value)
    }

    fun writeBytes(field: String, value: ByteArray, minimum: Int, maximum: Int) {
        if (value.size !in minimum..maximum) throw WireCodecException.InvalidLength(field)
        output.writeInt(value.size)
        output.write(value)
    }

    fun writeString(field: String, value: String, maximum: Int) {
        writeBytes(field, encodeUtf8(field, value), 1, maximum)
    }

    fun writeCollectionSize(field: String, value: Int, maximum: Int) {
        if (value !in 1..maximum) throw WireCodecException.InvalidLength(field)
        output.writeInt(value)
    }

    fun toByteArray(): ByteArray {
        output.flush()
        return bytes.toByteArray()
    }

    fun toFrame(): ByteArray {
        val body = toByteArray()
        if (body.size > NormalizedWireCodec.MAX_FRAME_BYTES - Int.SIZE_BYTES) {
            throw WireCodecException.OversizedFrame()
        }
        return ByteArrayOutputStream(body.size + Int.SIZE_BYTES).use { framedBytes ->
            DataOutputStream(framedBytes).use { framed ->
                framed.writeInt(body.size)
                framed.write(body)
            }
            framedBytes.toByteArray()
        }
    }
}

internal class WireReader(private val bytes: ByteArray, private var offset: Int) {
    fun readUnsignedByte(): Int {
        requireAvailable(Byte.SIZE_BYTES)
        return bytes[offset++].toInt() and 0xff
    }

    fun readUnsignedShort(): Int {
        requireAvailable(Short.SIZE_BYTES)
        val value = ByteBuffer.wrap(bytes, offset, Short.SIZE_BYTES).short.toInt() and 0xffff
        offset += Short.SIZE_BYTES
        return value
    }

    fun readInt(): Int {
        requireAvailable(Int.SIZE_BYTES)
        val value = ByteBuffer.wrap(bytes, offset, Int.SIZE_BYTES).int
        offset += Int.SIZE_BYTES
        return value
    }

    fun readLong(): Long {
        requireAvailable(Long.SIZE_BYTES)
        val value = ByteBuffer.wrap(bytes, offset, Long.SIZE_BYTES).long
        offset += Long.SIZE_BYTES
        return value
    }

    fun readULong(): ULong = readLong().toULong()

    fun readUuid() = UUID(readLong(), readLong())

    fun readInstant(): Instant {
        val epochSecond = readLong()
        val nano = readInt()
        if (nano !in 0..999_999_999) throw WireCodecException.MalformedFrame()
        return try {
            Instant.ofEpochSecond(epochSecond, nano.toLong())
        } catch (_: DateTimeException) {
            throw WireCodecException.MalformedFrame()
        }
    }

    fun readFixed(size: Int): ByteArray {
        requireAvailable(size)
        return bytes.copyOfRange(offset, offset + size).also { offset += size }
    }

    fun readBytes(field: String, minimum: Int, maximum: Int): ByteArray {
        val size = readInt()
        if (size !in minimum..maximum) throw WireCodecException.InvalidLength(field)
        return readFixed(size)
    }

    fun readString(field: String, maximum: Int): String =
        decodeUtf8(field, readBytes(field, 1, maximum))

    fun readCollectionSize(field: String, maximum: Int): Int {
        val size = readInt()
        if (size !in 1..maximum) throw WireCodecException.InvalidLength(field)
        return size
    }

    fun requireFinished() {
        if (offset != bytes.size) throw WireCodecException.TrailingData()
    }

    private fun requireAvailable(size: Int) {
        if (size < 0 || offset > bytes.size - size) throw WireCodecException.TruncatedFrame()
    }
}

private fun encodeUtf8(field: String, value: String): ByteArray =
    try {
        Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
            .let { encoded -> ByteArray(encoded.remaining()).also(encoded::get) }
    } catch (_: CharacterCodingException) {
        throw WireCodecException.InvalidUtf8(field)
    }

private fun decodeUtf8(field: String, value: ByteArray): String =
    try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(value))
            .toString()
    } catch (_: CharacterCodingException) {
        throw WireCodecException.InvalidUtf8(field)
    }
