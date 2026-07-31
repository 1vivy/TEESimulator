package org.matrix.TEESimulator.rka.journal

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

internal object RkpJournalCodec {
    private const val MAGIC = 0x524b4a31
    private const val MAX_BYTES = 131_072

    fun encode(record: RkpJournalRecord): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(MAGIC)
                output.writeByte(record.state.ordinal)
                output.write(record.batchId.copyBytes())
                output.writeByte(record.count)
                output.writeUTF(record.identity.descriptor)
                output.writeUTF(record.identity.serviceName)
                output.writeUTF(record.identity.componentName)
                output.writeUTF(record.identity.uniqueId)
                output.writeByte(record.identity.version)
                output.writeUTF(record.identity.securityLevel)
                output.writeUTF(record.identity.algorithm)
                output.writeUTF(record.identity.curve)
                output.write(record.identity.hash())
                output.writeByte(record.entries.size)
                record.entries.forEach { entry ->
                    val publicKey = entry.copyPublicKey()
                    val spkiDer = entry.copySpkiDer()
                    output.writeByte(entry.order)
                    output.writeShort(publicKey.size)
                    output.write(publicKey)
                    output.writeShort(spkiDer.size)
                    output.write(spkiDer)
                    output.write(entry.copyPublicHash())
                    output.write(entry.copySpkiHash())
                    output.write(entry.handle.copyBytes())
                }
            }
            bytes.toByteArray().also { require(it.size <= MAX_BYTES) }
        }

    fun decode(bytes: ByteArray): RkpJournalRecord {
        require(bytes.size <= MAX_BYTES)
        return DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == MAGIC)
            val state = RkpJournalState.entries[input.readUnsignedByte()]
            val batchId = RkpBatchId.from(input.readNBytes(16))
            val count = input.readUnsignedByte()
            val identity =
                RkpIrpcIdentity(
                    input.readUTF(),
                    input.readUTF(),
                    input.readUTF(),
                    input.readUTF(),
                    input.readUnsignedByte(),
                    input.readUTF(),
                    input.readUTF(),
                    input.readUTF(),
                )
            require(input.readNBytes(32).contentEquals(identity.hash()))
            val entries =
                List(input.readUnsignedByte()) {
                    val order = input.readUnsignedByte()
                    val publicKey = input.readNBytes(input.readUnsignedShort())
                    val spkiDer = input.readNBytes(input.readUnsignedShort())
                    val publicHash = input.readNBytes(32)
                    val spkiHash = input.readNBytes(32)
                    val handle = RkpOpaqueHandle.from(input.readNBytes(32))
                    require(publicHash.contentEquals(sha256(publicKey)))
                    require(spkiHash.contentEquals(sha256(spkiDer)))
                    require(
                        handle.matches(RkpOpaqueHandle.derive(batchId, order, publicHash, spkiHash))
                    )
                    RkpJournalEntry(order, publicKey, spkiDer, publicHash, spkiHash, handle)
                }
            require(input.read() == -1)
            RkpJournalRecord(batchId, state, count, identity, entries)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
}
