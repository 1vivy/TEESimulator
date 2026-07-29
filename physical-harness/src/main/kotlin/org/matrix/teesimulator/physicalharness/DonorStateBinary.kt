package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID

internal class DonorStateWriter(private val maximumBytes: Int) {
    private val output = ByteArrayOutputStream()
    private val stream = DataOutputStream(output)

    fun writeByte(value: Int) {
        reserve(1)
        stream.writeByte(value)
    }

    fun writeUnsignedShort(value: Int) {
        reserve(2)
        stream.writeShort(value)
    }

    fun writeInt(value: Int) {
        reserve(4)
        stream.writeInt(value)
    }

    fun writeLong(value: Long) {
        reserve(8)
        stream.writeLong(value)
    }

    fun writeFixed(value: ByteArray) {
        reserve(value.size)
        stream.write(value)
    }

    fun writeBytes(value: ByteArray) {
        writeInt(value.size)
        writeFixed(value)
    }

    fun writeString(value: String) = writeBytes(value.toByteArray(StandardCharsets.UTF_8))

    fun writeUuid(value: UUID) {
        writeLong(value.mostSignificantBits)
        writeLong(value.leastSignificantBits)
    }

    fun toByteArray(): ByteArray = output.toByteArray()

    private fun reserve(count: Int) {
        if (count < 0 || output.size() > maximumBytes - count) {
            throw DonorStateQuarantineException.InvalidRecord()
        }
    }
}

internal class DonorStateReader(private val input: ByteArray) {
    private var position = 0

    val remaining: Int
        get() = input.size - position

    fun readUnsignedByte(): Int {
        requireRemaining(1)
        return input[position++].toInt() and 0xff
    }

    fun readUnsignedShort(): Int {
        requireRemaining(2)
        val value = ByteBuffer.wrap(input, position, 2).short.toInt() and 0xffff
        position += 2
        return value
    }

    fun readInt(): Int {
        requireRemaining(4)
        val value = ByteBuffer.wrap(input, position, 4).int
        position += 4
        return value
    }

    fun readLong(): Long {
        requireRemaining(8)
        val value = ByteBuffer.wrap(input, position, 8).long
        position += 8
        return value
    }

    fun readFixed(size: Int): ByteArray {
        if (size < 0) throw DonorStateCorruptionException.LimitExceeded()
        requireRemaining(size)
        return input.copyOfRange(position, position + size).also { position += size }
    }

    fun readBytes(minimum: Int, maximum: Int): ByteArray {
        val size = readInt()
        if (size !in minimum..maximum) throw DonorStateCorruptionException.LimitExceeded()
        return readFixed(size)
    }

    fun readString(minimum: Int, maximum: Int): String {
        val bytes = readBytes(minimum, maximum)
        val decoder =
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            throw DonorStateCorruptionException.InvalidUtf8()
        }
    }

    fun readCount(maximum: Int): Int {
        val count = readInt()
        if (count !in 0..maximum) throw DonorStateCorruptionException.LimitExceeded()
        return count
    }

    fun readUuid() = UUID(readLong(), readLong())

    fun requireFinished() {
        if (remaining != 0) throw DonorStateCorruptionException.TrailingData()
    }

    private fun requireRemaining(count: Int) {
        if (count < 0 || remaining < count) throw DonorStateCorruptionException.Truncated()
    }
}
