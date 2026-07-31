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
        val request =
            message is BridgeMessage.PublicKeyRequest ||
                message is BridgeMessage.UpdateRequest ||
                message is BridgeMessage.Cancel ||
                message is BridgeMessage.CandidateCommand
        val role =
            when (direction) {
                BridgeDirection.SIDECAR_TO_BROKER ->
                    if (request) BridgeExchangeRole.DONOR_REQUEST
                    else BridgeExchangeRole.CANDIDATE_RESPONSE
                BridgeDirection.BROKER_TO_SIDECAR ->
                    if (request) BridgeExchangeRole.CANDIDATE_REQUEST
                    else BridgeExchangeRole.DONOR_RESPONSE
            }
        return encode(message, role)
    }

    fun encode(message: BridgeMessage, role: BridgeExchangeRole): ByteArray {
        val tag = BridgeProtocol.tagOf(message)
        require(tag in role.tags)
        val body = encodeBody(message)
        require(body.size in 1..BridgeLimits.MAX_FRAME_BYTES)
        return try {
            headerForTest(role.direction, tag, message.requestId.value, body.size.toLong()) + body
        } finally {
            body.fill(0)
        }
    }

    fun decode(input: InputStream, role: BridgeExchangeRole): BridgeResult<BridgeMessage> {
        val header = ByteArray(BridgeLimits.HEADER_BYTES)
        return try {
            if (!readExactly(input, header)) return BridgeResult.Failure(BridgeError.Truncated)
            val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
            if (buffer.int != BridgeLimits.MAGIC) return BridgeResult.Failure(BridgeError.BadMagic)
            if (buffer.get().toInt() and 0xff != BridgeLimits.VERSION) {
                return BridgeResult.Failure(BridgeError.UnsupportedVersion)
            }
            if (buffer.get().toInt() and 0xff != role.direction.wire) {
                return BridgeResult.Failure(BridgeError.WrongDirection)
            }
            val tag = buffer.get().toInt() and 0xff
            if (tag !in BridgeTag.known) return BridgeResult.Failure(BridgeError.UnknownTag)
            if (tag !in role.tags) return BridgeResult.Failure(BridgeError.UnexpectedTag)
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
            try {
                if (!readExactly(input, body)) return BridgeResult.Failure(BridgeError.Truncated)
                decodeBody(tag, RequestId(requestId), body)
            } finally {
                body.fill(0)
            }
        } finally {
            header.fill(0)
        }
    }

    fun decode(
        input: InputStream,
        expectedDirection: BridgeDirection,
    ): BridgeResult<BridgeMessage> =
        decode(
            input,
            when (expectedDirection) {
                BridgeDirection.SIDECAR_TO_BROKER -> BridgeExchangeRole.DONOR_REQUEST
                BridgeDirection.BROKER_TO_SIDECAR -> BridgeExchangeRole.CANDIDATE_REQUEST
            },
        )

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
                        writeBytes(out, message.challenge)
                    }
                    is BridgeMessage.PublicKeyResponse -> {
                        writeBytes(out, message.publicCsr)
                        val hashes = message.publicKeyHashes()
                        try {
                            out.writeByte(hashes.size)
                            hashes.forEach { writeFixed(out, it) }
                        } finally {
                            hashes.forEach(Hash32::close)
                        }
                    }
                    is BridgeMessage.UpdateRequest -> {
                        writeFixed(out, message.operationHandle)
                        out.writeInt(message.totalInputBytes)
                        writeBytes(out, message.chunk)
                    }
                    is BridgeMessage.PublicResult -> {
                        writeFixed(out, message.networkHandle)
                        writeBytes(out, message.publicSpki)
                        val chain = message.certificateChain()
                        try {
                            out.writeByte(chain.size)
                            chain.forEach { writeBytes(out, it) }
                        } finally {
                            chain.forEach(PublicBytes::close)
                        }
                    }
                    is BridgeMessage.Cancel -> out.writeByte(0)
                    is BridgeMessage.Error -> {
                        out.writeByte(message.code.wire)
                        writeFixed(out, message.detailHash)
                    }
                    is BridgeMessage.CandidateCommand -> {
                        out.writeByte(message.operation.wire)
                        writeBytes(out, message.payload)
                    }
                    is BridgeMessage.CandidateReply -> {
                        out.writeByte(message.operation.wire)
                        writeBytes(out, message.payload)
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
                        val challenge = readPublicBytes(input, 64, minimum = 16)
                        try {
                            BridgeMessage.PublicKeyRequest(requestId, challenge, count)
                        } catch (error: Throwable) {
                            challenge.close()
                            throw error
                        }
                    }
                    BridgeTag.PUBLIC_KEY_RESPONSE -> {
                        val csr = readPublicBytes(input, BridgeLimits.MAX_FRAME_BYTES, minimum = 1)
                        val count = input.readUnsignedByte()
                        val hashes = mutableListOf<Hash32>()
                        try {
                            require(count in 1..BridgeLimits.MAX_PUBLIC_KEYS)
                            repeat(count) { hashes += readHash(input) }
                            BridgeMessage.PublicKeyResponse(requestId, csr, hashes)
                        } catch (error: Throwable) {
                            csr.close()
                            hashes.forEach(Hash32::close)
                            throw error
                        }
                    }
                    BridgeTag.UPDATE_REQUEST -> {
                        val handle = readHandle(input)
                        val total = input.readInt()
                        val chunk = readPublicBytes(input, BridgeLimits.MAX_UPDATE_BYTES)
                        try {
                            BridgeMessage.UpdateRequest(requestId, handle, chunk, total)
                        } catch (error: Throwable) {
                            handle.close()
                            chunk.close()
                            throw error
                        }
                    }
                    BridgeTag.PUBLIC_RESULT -> {
                        val handle = readHandle(input)
                        val spki =
                            readPublicBytes(input, BridgeLimits.MAX_CERTIFICATE_BYTES, minimum = 1)
                        val count = input.readUnsignedByte()
                        val chain = mutableListOf<PublicBytes>()
                        var total = 0L
                        try {
                            require(count in 1..BridgeLimits.MAX_CHAIN_CERTIFICATES)
                            repeat(count) {
                                val length =
                                    readLength(
                                        input,
                                        BridgeLimits.MAX_CERTIFICATE_BYTES,
                                        minimum = 1,
                                    )
                                total = Math.addExact(total, length.toLong())
                                require(total <= BridgeLimits.MAX_CHAIN_BYTES)
                                chain +=
                                    readPublicBytesOfLength(
                                        input,
                                        length,
                                        BridgeLimits.MAX_CERTIFICATE_BYTES,
                                    )
                            }
                            BridgeMessage.PublicResult(requestId, handle, spki, chain)
                        } catch (error: Throwable) {
                            handle.close()
                            spki.close()
                            chain.forEach(PublicBytes::close)
                            throw error
                        }
                    }
                    BridgeTag.CANCEL -> {
                        require(input.readUnsignedByte() == 0)
                        BridgeMessage.Cancel(requestId)
                    }
                    BridgeTag.ERROR -> {
                        val codeValue = input.readUnsignedByte()
                        val code = BridgeErrorCode.entries.singleOrNull { it.wire == codeValue }
                        requireNotNull(code)
                        BridgeMessage.Error(requestId, code, readHash(input))
                    }
                    BridgeTag.CANDIDATE_COMMAND,
                    BridgeTag.CANDIDATE_REPLY -> {
                        val operationValue = input.readUnsignedByte()
                        val operation =
                            CandidateBridgeOperation.entries.singleOrNull {
                                it.wire == operationValue
                            }
                        requireNotNull(operation)
                        val payload = readPublicBytes(input, BridgeLimits.MAX_FRAME_BYTES - 5)
                        if (tag == BridgeTag.CANDIDATE_COMMAND) {
                            BridgeMessage.CandidateCommand(requestId, operation, payload)
                        } else {
                            BridgeMessage.CandidateReply(requestId, operation, payload)
                        }
                    }
                    else -> return BridgeResult.Failure(BridgeError.UnknownTag)
                }
            if (input.available() != 0) {
                message.close()
                BridgeResult.Failure(BridgeError.NonCanonical)
            } else {
                BridgeResult.Success(message)
            }
        } catch (_: EOFException) {
            BridgeResult.Failure(BridgeError.Truncated)
        } catch (_: IllegalArgumentException) {
            BridgeResult.Failure(BridgeError.NonCanonical)
        }

    private fun writeBytes(output: DataOutputStream, bytes: PublicBytes) {
        val copy = bytes.copyBytes()
        try {
            output.writeInt(copy.size)
            output.write(copy)
        } finally {
            copy.fill(0)
        }
    }

    private fun writeFixed(output: DataOutputStream, value: Hash32) {
        val copy = value.copyBytes()
        try {
            output.write(copy)
        } finally {
            copy.fill(0)
        }
    }

    private fun writeFixed(output: DataOutputStream, value: NetworkHandle) {
        val copy = value.copyBytes()
        try {
            output.write(copy)
        } finally {
            copy.fill(0)
        }
    }

    private fun readPublicBytes(
        input: DataInputStream,
        maximum: Int,
        minimum: Int = 0,
    ): PublicBytes {
        val length = readLength(input, maximum, minimum)
        return readPublicBytesOfLength(input, length, maximum)
    }

    private fun readLength(input: DataInputStream, maximum: Int, minimum: Int): Int {
        val unsignedLength = input.readInt().toLong() and 0xffff_ffffL
        require(unsignedLength in minimum.toLong()..maximum.toLong())
        return unsignedLength.toInt()
    }

    private fun readPublicBytesOfLength(
        input: DataInputStream,
        length: Int,
        maximum: Int,
    ): PublicBytes {
        val bytes = readFixed(input, length)
        return try {
            PublicBytes.of(bytes, maximum)
        } finally {
            bytes.fill(0)
        }
    }

    private fun readHash(input: DataInputStream): Hash32 {
        val bytes = readFixed(input, 32)
        return try {
            Hash32.of(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun readHandle(input: DataInputStream): NetworkHandle {
        val bytes = readFixed(input, 16)
        return try {
            NetworkHandle.of(bytes)
        } finally {
            bytes.fill(0)
        }
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
