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
                output.writeByte(record.irpcVersion)
                output.writeUTF(record.securityLevel)
                output.writeUTF(record.curve)
                output.writeByte(record.entries.size)
                record.entries.forEach { entry ->
                    val publicKey = entry.copyPublicKey()
                    output.writeByte(entry.order)
                    output.writeShort(publicKey.size)
                    output.write(publicKey)
                    output.write(entry.copyPublicHash())
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
            val version = input.readUnsignedByte()
            val security = input.readUTF()
            val curve = input.readUTF()
            val entries =
                List(input.readUnsignedByte()) {
                    val order = input.readUnsignedByte()
                    val publicKey = input.readNBytes(input.readUnsignedShort())
                    val hash = input.readNBytes(32)
                    val handle = RkpOpaqueHandle.from(input.readNBytes(32))
                    require(
                        hash.contentEquals(
                            java.security.MessageDigest.getInstance("SHA-256").digest(publicKey)
                        )
                    )
                    require(handle.matches(RkpOpaqueHandle.derive(batchId, order, hash)))
                    RkpJournalEntry(order, publicKey, hash, handle)
                }
            require(input.read() == -1)
            RkpJournalRecord(batchId, state, count, version, security, curve, entries)
        }
    }
}
