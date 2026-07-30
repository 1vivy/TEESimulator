package org.matrix.teesimulator.rka

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

object RkaReferenceCodec {
    const val HEADER_SIZE = 322
    const val MAX_FRAME_SIZE = RkaLimits.FRAME_BYTES
    private val magic = byteArrayOf(0x52, 0x4b, 0x41, 0x31)

    fun encode(frame: RkaFrame): ByteArray {
        require(frame.sessionId.size == 32)
        require(frame.requestId.size == 16)
        require(frame.clientNonce.size == 32)
        require(frame.serverNonce.size == 32)
        require(frame.candidateTlsPin.size == 32)
        require(frame.peerTlsPin.size == 32)
        require(frame.donorFingerprint.size == 32)
        require(frame.callerIdentityHash.size == 32)
        require(HEADER_SIZE + frame.payload.size <= MAX_FRAME_SIZE)
        RkaPayloadCodec.decode(frame)
        return java.io.ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(magic)
                output.writeShort(1)
                output.writeByte(frame.kind.tag)
                output.writeByte(frame.transport.tag)
                output.writeByte(frame.method.tag)
                output.writeShort(frame.error.tag)
                output.writeByte(0)
                output.writeShort(HEADER_SIZE)
                output.writeInt(HEADER_SIZE + frame.payload.size)
                output.writeULong(frame.profileEpoch)
                output.writeULong(frame.sequence)
                output.writeULong(frame.deadlineUnixMillis)
                output.write(frame.sessionId)
                output.write(frame.requestId)
                output.write(frame.clientNonce)
                output.write(frame.serverNonce)
                output.write(frame.candidateTlsPin)
                output.write(frame.peerTlsPin)
                output.write(frame.donorFingerprint)
                output.writeInt(frame.callerUid.toInt())
                output.write(frame.callerIdentityHash)
                output.write(MessageDigest.getInstance("SHA-256").digest(frame.payload))
                output.writeInt(frame.payload.size)
                output.write(frame.payload)
            }
            bytes.toByteArray()
        }
    }

    fun decode(encoded: ByteArray): RkaFrame = decodeFraming(encoded).also(RkaPayloadCodec::decode)

    fun decodeFraming(encoded: ByteArray): RkaFrame {
        require(encoded.size in HEADER_SIZE..MAX_FRAME_SIZE)
        return DataInputStream(ByteArrayInputStream(encoded)).use { input ->
            require(input.readNBytes(4).contentEquals(magic))
            require(input.readUnsignedShort() == 1)
            val kind = MessageKind.fromTag(input.readUnsignedByte())
            val transport = TransportKind.fromTag(input.readUnsignedByte())
            val method = Method.fromTag(input.readUnsignedByte())
            val error = ErrorCode.fromTag(input.readUnsignedShort())
            require(input.readUnsignedByte() == 0)
            require(input.readUnsignedShort() == HEADER_SIZE)
            require(input.readInt() == encoded.size)
            val profileEpoch = input.readULong()
            val sequence = input.readULong()
            val deadline = input.readULong()
            val sessionId = input.readNBytes(32)
            val requestId = input.readNBytes(16)
            val clientNonce = input.readNBytes(32)
            val serverNonce = input.readNBytes(32)
            val candidatePin = input.readNBytes(32)
            val peerPin = input.readNBytes(32)
            val donorFingerprint = input.readNBytes(32)
            val callerUid = input.readInt().toUInt()
            val callerIdentityHash = input.readNBytes(32)
            val payloadHash = input.readNBytes(32)
            val payloadLength = input.readInt()
            require(payloadLength == encoded.size - HEADER_SIZE)
            val payload = input.readNBytes(payloadLength)
            require(payload.size == payloadLength)
            require(payloadHash.contentEquals(MessageDigest.getInstance("SHA-256").digest(payload)))
            RkaFrame(
                kind,
                transport,
                method,
                error,
                profileEpoch,
                sequence,
                deadline,
                sessionId,
                requestId,
                clientNonce,
                serverNonce,
                candidatePin,
                peerPin,
                donorFingerprint,
                callerUid,
                callerIdentityHash,
                payload,
            )
        }
    }

    private fun DataOutputStream.writeULong(value: ULong) {
        writeLong(value.toLong())
    }

    private fun DataInputStream.readULong(): ULong = readLong().toULong()
}
