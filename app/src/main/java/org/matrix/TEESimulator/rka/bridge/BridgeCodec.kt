package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object BridgeCodec {
    fun encode(message: BridgeMessage, direction: BridgeDirection): ByteArray {
        val tag =
            when (message) {
                is BridgeMessage.PublicKeyRequest -> BridgeTag.PUBLIC_KEY_REQUEST
                is BridgeMessage.PublicKeyResponse -> BridgeTag.PUBLIC_KEY_RESPONSE
                is BridgeMessage.UpdateRequest -> BridgeTag.UPDATE_REQUEST
                is BridgeMessage.PublicResult -> BridgeTag.PUBLIC_RESULT
                is BridgeMessage.Cancel -> BridgeTag.CANCEL
                is BridgeMessage.Error -> BridgeTag.ERROR
            }
        val body = encodeBody(message)
        require(body.size in 1..BridgeLimits.MAX_FRAME_BYTES)
        return try {
            headerForTest(direction, tag, message.requestId.value, body.size.toLong()) + body
        } finally {
            body.fill(0)
        }
    }

    fun decode(
        input: InputStream,
        expectedDirection: BridgeDirection,
    ): BridgeResult<BridgeMessage> {
        val header = ByteArray(BridgeLimits.HEADER_BYTES)
        if (!readExactly(input, header)) return BridgeResult.Failure(BridgeError.Truncated)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        if (buffer.int != BridgeLimits.MAGIC) return BridgeResult.Failure(BridgeError.BadMagic)
        if (buffer.get().toInt() and 0xff != BridgeLimits.VERSION) {
            return BridgeResult.Failure(BridgeError.UnsupportedVersion)
        }
        if (buffer.get().toInt() and 0xff != expectedDirection.wire) {
            return BridgeResult.Failure(BridgeError.WrongDirection)
        }
        val tag = buffer.get().toInt() and 0xff
        if (tag !in BridgeTag.known) return BridgeResult.Failure(BridgeError.UnknownTag)
        val flags = buffer.get().toInt() and 0xff
        val requestId = buffer.long
        val unsignedLength = buffer.int.toLong() and 0xffff_ffffL
        val reserved = buffer.int
        if (flags != 0 || reserved != 0) return BridgeResult.Failure(BridgeError.ReservedBits)
        if (unsignedLength == 0L) return BridgeResult.Failure(BridgeError.EmptyFrame)
        if (unsignedLength > BridgeLimits.MAX_FRAME_BYTES) {
            return BridgeResult.Failure(BridgeError.FrameTooLarge)
        }
        val body = ByteArray(unsignedLength.toInt())
        if (!readExactly(input, body)) {
            body.fill(0)
            return BridgeResult.Failure(BridgeError.Truncated)
        }
        return try {
            decodeBody(tag, RequestId(requestId), body)
        } finally {
            body.fill(0)
        }
    }

    fun headerForTest(
        direction: BridgeDirection,
        tag: Int,
        requestId: Long,
        bodyLength: Long,
        flags: Int = 0,
    ): ByteArray =
        ByteBuffer.allocate(BridgeLimits.HEADER_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(BridgeLimits.MAGIC)
            .put(BridgeLimits.VERSION.toByte())
            .put(direction.wire.toByte())
            .put(tag.toByte())
            .put(flags.toByte())
            .putLong(requestId)
            .putInt(bodyLength.toInt())
            .putInt(0)
            .array()

    private fun encodeBody(message: BridgeMessage): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                when (message) {
                    is BridgeMessage.PublicKeyRequest -> {
                        out.writeByte(message.keyCount)
                        writeBytes(out, message.challenge.copyBytes())
                    }
                    is BridgeMessage.PublicKeyResponse -> {
                        writeBytes(out, message.publicCsr.copyBytes())
                        val hashes = message.publicKeyHashes()
                        out.writeByte(hashes.size)
                        hashes.forEach { out.write(it.copyBytes()) }
                    }
                    is BridgeMessage.UpdateRequest -> {
                        out.write(message.operationHandle.copyBytes())
                        out.writeInt(message.totalInputBytes)
                        writeBytes(out, message.chunk.copyBytes())
                    }
                    is BridgeMessage.PublicResult -> {
                        out.write(message.networkHandle.copyBytes())
                        writeBytes(out, message.publicSpki.copyBytes())
                        val chain = message.certificateChain()
                        out.writeByte(chain.size)
                        chain.forEach { writeBytes(out, it.copyBytes()) }
                    }
                    is BridgeMessage.Cancel -> out.writeByte(0)
                    is BridgeMessage.Error -> {
                        out.writeByte(message.code.wire)
                        out.write(message.detailHash.copyBytes())
                    }
                }
            }
            bytes.toByteArray()
        }

    private fun decodeBody(
        tag: Int,
        requestId: RequestId,
        body: ByteArray,
    ): BridgeResult<BridgeMessage> =
        try {
            val input = DataInputStream(ByteArrayInputStream(body))
            val message =
                when (tag) {
                    BridgeTag.PUBLIC_KEY_REQUEST -> {
                        val count = input.readUnsignedByte()
                        val challenge = readBytes(input, 64, minimum = 16)
                        BridgeMessage.PublicKeyRequest(
                            requestId,
                            PublicBytes.of(challenge, 64),
                            count,
                        )
                    }
                    BridgeTag.PUBLIC_KEY_RESPONSE -> {
                        val csr = readBytes(input, BridgeLimits.MAX_FRAME_BYTES, minimum = 1)
                        val count = input.readUnsignedByte()
                        require(count in 1..BridgeLimits.MAX_PUBLIC_KEYS)
                        val hashes = List(count) { Hash32.of(readFixed(input, 32)) }
                        BridgeMessage.PublicKeyResponse(
                            requestId,
                            PublicBytes.of(csr, BridgeLimits.MAX_FRAME_BYTES),
                            hashes,
                        )
                    }
                    BridgeTag.UPDATE_REQUEST -> {
                        val handle = NetworkHandle.of(readFixed(input, 16))
                        val total = input.readInt()
                        val chunk = readBytes(input, BridgeLimits.MAX_UPDATE_BYTES)
                        BridgeMessage.UpdateRequest(
                            requestId,
                            handle,
                            PublicBytes.of(chunk, BridgeLimits.MAX_UPDATE_BYTES),
                            total,
                        )
                    }
                    BridgeTag.PUBLIC_RESULT -> {
                        val handle = NetworkHandle.of(readFixed(input, 16))
                        val spki = readBytes(input, BridgeLimits.MAX_CERTIFICATE_BYTES, minimum = 1)
                        val count = input.readUnsignedByte()
                        require(count in 1..BridgeLimits.MAX_CHAIN_CERTIFICATES)
                        val chain =
                            List(count) {
                                PublicBytes.of(
                                    readBytes(
                                        input,
                                        BridgeLimits.MAX_CERTIFICATE_BYTES,
                                        minimum = 1,
                                    ),
                                    BridgeLimits.MAX_CERTIFICATE_BYTES,
                                )
                            }
                        BridgeMessage.PublicResult(
                            requestId,
                            handle,
                            PublicBytes.of(spki, BridgeLimits.MAX_CERTIFICATE_BYTES),
                            chain,
                        )
                    }
                    BridgeTag.CANCEL -> {
                        require(input.readUnsignedByte() == 0)
                        BridgeMessage.Cancel(requestId)
                    }
                    BridgeTag.ERROR -> {
                        val codeValue = input.readUnsignedByte()
                        val code = BridgeErrorCode.entries.singleOrNull { it.wire == codeValue }
                        requireNotNull(code)
                        BridgeMessage.Error(requestId, code, Hash32.of(readFixed(input, 32)))
                    }
                    else -> return BridgeResult.Failure(BridgeError.UnknownTag)
                }
            if (input.available() != 0) {
                BridgeResult.Failure(BridgeError.NonCanonical)
            } else {
                BridgeResult.Success(message)
            }
        } catch (_: EOFException) {
            BridgeResult.Failure(BridgeError.Truncated)
        } catch (_: IllegalArgumentException) {
            BridgeResult.Failure(BridgeError.NonCanonical)
        }

    private fun writeBytes(output: DataOutputStream, bytes: ByteArray) {
        output.writeInt(bytes.size)
        output.write(bytes)
    }

    private fun readBytes(input: DataInputStream, maximum: Int, minimum: Int = 0): ByteArray {
        val unsignedLength = input.readInt().toLong() and 0xffff_ffffL
        require(unsignedLength in minimum.toLong()..maximum.toLong())
        return readFixed(input, unsignedLength.toInt())
    }

    private fun readFixed(input: DataInputStream, size: Int): ByteArray =
        ByteArray(size).also { input.readFully(it) }

    private fun readExactly(input: InputStream, destination: ByteArray): Boolean {
        var offset = 0
        while (offset < destination.size) {
            val read = input.read(destination, offset, destination.size - offset)
            if (read < 0) return false
            if (read == 0) continue
            offset += read
        }
        return true
    }
}

/**
 * Cross-language golden consumed by Task 8. Header fields are:
 * magic/version/direction/tag/flags/request-id/body-length/reserved, all integers big-endian.
 */
val BRIDGE_GOLDEN_PUBLIC_KEY_REQUEST: ByteArray =
    byteArrayOf(
        0x52,
        0x4b,
        0x42,
        0x31,
        0x01,
        0x01,
        0x01,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x00,
        0x00,
        0x00,
        0x15,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    )
