package org.matrix.teesimulator.twophone

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal data class PublicProfileFieldSpec(
    val tag: Int,
    val minimum: Int,
    val maximum: Int,
    val exact: Int? = null,
)

internal object PublicProfileBinary {
    const val PIN_BYTES = 32
    const val SIGNER_DIGEST_BYTES = 32
    const val MAX_PACKAGE_BYTES = 255
    const val MAX_ALIAS_BYTES = 128
    const val MAX_CERTIFICATE_BYTES = 64 * 1024
    const val MAX_CERTIFICATES = 8
    const val MAX_CHAIN_BYTES = MAX_CERTIFICATE_BYTES * MAX_CERTIFICATES + 34

    fun encode(magic: Int, fields: List<Pair<Int, ByteArray>>): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.writeInt(magic)
            writer.writeShort(1)
            fields.forEach { (tag, value) ->
                if (value.isEmpty()) throw PublicProfileException.InvalidFieldLength(tag)
                writer.writeShort(tag)
                writer.writeInt(value.size)
                writer.write(value)
            }
        }
        val encoded = output.toByteArray()
        if (encoded.size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw PublicProfileException.OversizedProfile()
        }
        return encoded
    }

    fun reader(input: ByteArray, magic: Int): PublicProfileReader {
        if (input.size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw PublicProfileException.OversizedProfile()
        }
        if (input.size < 6) throw PublicProfileException.Truncated()
        val reader = PublicProfileReader(input)
        if (reader.readHeaderInt() != magic) throw PublicProfileException.InvalidMagic()
        val version = reader.readHeaderUnsignedShort()
        if (version != 1) throw PublicProfileException.UnknownVersion(version)
        return reader
    }

    fun long(value: Long): ByteArray = ByteBuffer.allocate(8).putLong(value).array()

    fun int(value: Int): ByteArray = ByteBuffer.allocate(4).putInt(value).array()

    fun pin(value: PublicProfilePin): ByteArray = value.digest

    fun text(field: Int, value: String): ByteArray =
        try {
            StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(java.nio.CharBuffer.wrap(value))
                .let { bytes -> ByteArray(bytes.remaining()).also(bytes::get) }
        } catch (_: CharacterCodingException) {
            throw PublicProfileException.InvalidUtf8(field)
        }

    fun endpoint(value: ProfileEndpoint): ByteArray =
        ByteBuffer.allocate(1 + value.address.size + 2)
            .put(value.address.size.toByte())
            .put(value.address)
            .putShort(value.port.toShort())
            .array()

    fun chain(field: Int, certificates: List<ByteArray>): ByteArray {
        if (certificates.size !in 2..MAX_CERTIFICATES) {
            throw PublicProfileException.InvalidFieldLength(field)
        }
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.writeShort(certificates.size)
            certificates.forEach { certificate ->
                if (certificate.size !in 1..MAX_CERTIFICATE_BYTES) {
                    throw PublicProfileException.OversizedField(field)
                }
                writer.writeInt(certificate.size)
                writer.write(certificate)
            }
        }
        return output.toByteArray()
    }
}

internal class PublicProfileReader(private val input: ByteArray) {
    private var offset = 0
    private val seen = mutableSetOf<Int>()

    fun read(spec: PublicProfileFieldSpec): ByteArray {
        requireRemaining(6)
        val actualTag = readUnsignedShort()
        if (actualTag != spec.tag) {
            if (actualTag in seen) throw PublicProfileException.DuplicateField(actualTag)
            throw PublicProfileException.UnexpectedField(actualTag)
        }
        seen += actualTag
        val length = readInt()
        if (length < 0 || length > spec.maximum) {
            throw PublicProfileException.OversizedField(spec.tag)
        }
        if (length < spec.minimum || (spec.exact != null && length != spec.exact)) {
            throw PublicProfileException.InvalidFieldLength(spec.tag)
        }
        requireRemaining(length)
        return input.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun finish() {
        if (offset == input.size) return
        if (input.size - offset < 2) throw PublicProfileException.Truncated()
        val tag = ByteBuffer.wrap(input, offset, 2).short.toInt() and 0xffff
        if (tag in PublicProfileField.all) throw PublicProfileException.DuplicateField(tag)
        throw PublicProfileException.UnexpectedField(tag)
    }

    fun readHeaderInt(): Int = readInt()

    fun readHeaderUnsignedShort(): Int = readUnsignedShort()

    private fun readUnsignedShort(): Int {
        requireRemaining(2)
        val value = ByteBuffer.wrap(input, offset, 2).short.toInt() and 0xffff
        offset += 2
        return value
    }

    private fun readInt(): Int {
        requireRemaining(4)
        val value = ByteBuffer.wrap(input, offset, 4).int
        offset += 4
        return value
    }

    private fun requireRemaining(count: Int) {
        if (count < 0 || offset > input.size - count) throw PublicProfileException.Truncated()
    }
}

internal fun decodeProfileText(field: Int, value: ByteArray): String =
    try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(value))
            .toString()
    } catch (_: CharacterCodingException) {
        throw PublicProfileException.InvalidUtf8(field)
    }

internal fun decodeProfileLong(value: ByteArray): Long = ByteBuffer.wrap(value).long

internal fun decodeProfileInt(value: ByteArray): Int = ByteBuffer.wrap(value).int

internal fun decodeProfilePin(value: ByteArray): PublicProfilePin =
    PublicProfilePin.fromDigest(value)

internal fun decodeProfileEndpoint(value: ByteArray): ProfileEndpoint {
    if (value.size < 1) throw PublicProfileException.InvalidEndpoint()
    val addressSize = value[0].toInt() and 0xff
    if (addressSize !in setOf(4, 16) || value.size != addressSize + 3) {
        throw PublicProfileException.InvalidEndpoint()
    }
    val address = value.copyOfRange(1, 1 + addressSize)
    val port = ByteBuffer.wrap(value, 1 + addressSize, 2).short.toInt() and 0xffff
    return ProfileEndpoint.create(address, port)
}

internal fun decodeProfileChain(field: Int, value: ByteArray): List<ByteArray> {
    if (value.size < 2) throw PublicProfileException.InvalidFieldLength(field)
    val buffer = ByteBuffer.wrap(value)
    val count = buffer.short.toInt() and 0xffff
    if (count !in 2..PublicProfileBinary.MAX_CERTIFICATES) {
        throw PublicProfileException.InvalidFieldLength(field)
    }
    return List(count) {
            if (buffer.remaining() < 4) throw PublicProfileException.Truncated()
            val length = buffer.int
            if (length < 0 || length > PublicProfileBinary.MAX_CERTIFICATE_BYTES) {
                throw PublicProfileException.OversizedField(field)
            }
            if (length == 0) throw PublicProfileException.InvalidFieldLength(field)
            if (buffer.remaining() < length) throw PublicProfileException.Truncated()
            ByteArray(length).also(buffer::get)
        }
        .also { if (buffer.hasRemaining()) throw PublicProfileException.TrailingData() }
}
