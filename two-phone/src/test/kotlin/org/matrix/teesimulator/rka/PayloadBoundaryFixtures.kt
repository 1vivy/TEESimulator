package org.matrix.teesimulator.rka

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

object PayloadBoundaryFixtures {
    fun generateRequest(
        logicalName: ByteArray = "fixture-signing-key".encodeToByteArray(),
        challenge: ByteArray = ByteArray(32),
        purpose: Int = 1,
        digest: Int = 1,
        curve: Int = 1,
    ): ByteArray = bytes {
        writeSized16(logicalName)
        writeSized16(challenge)
        write(ByteArray(16))
        writeByte(purpose)
        writeByte(digest)
        writeByte(curve)
    }

    fun publicMetadataResponse(
        publicKey: ByteArray = byteArrayOf(0x30),
        certificates: List<ByteArray> = listOf(byteArrayOf(0x30)),
    ): ByteArray = bytes {
        write(ByteArray(32))
        writeSized16(publicKey)
        writeByte(certificates.size)
        certificates.forEach { certificate -> writeSized32(certificate) }
    }

    fun updateRequest(input: ByteArray): ByteArray = bytes {
        write(ByteArray(32))
        writeInt(0)
        writeSized32(input)
    }

    fun finishRequest(input: ByteArray, signature: ByteArray = byteArrayOf()): ByteArray = bytes {
        write(ByteArray(32))
        writeSized32(input)
        writeSized32(signature)
    }

    fun bytes(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use(block)
            bytes.toByteArray()
        }

    private fun DataOutputStream.writeSized16(value: ByteArray) {
        writeShort(value.size)
        write(value)
    }

    private fun DataOutputStream.writeSized32(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }
}
