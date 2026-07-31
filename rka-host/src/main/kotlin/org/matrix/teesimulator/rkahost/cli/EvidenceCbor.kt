package org.matrix.teesimulator.rkahost.cli

object EvidenceCbor {
    fun encode(value: String): ByteArray {
        val payload = value.toByteArray()
        val prefix =
            when {
                payload.size < 24 -> byteArrayOf((0x60 + payload.size).toByte())
                payload.size <= 0xff -> byteArrayOf(0x78, payload.size.toByte())
                payload.size <= 0xffff ->
                    byteArrayOf(0x79, (payload.size shr 8).toByte(), payload.size.toByte())
                else ->
                    byteArrayOf(
                        0x7a,
                        (payload.size shr 24).toByte(),
                        (payload.size shr 16).toByte(),
                        (payload.size shr 8).toByte(),
                        payload.size.toByte(),
                    )
            }
        return prefix + payload
    }

    fun decode(raw: ByteArray): String {
        if (raw.isEmpty()) throw HostCliException("EVIDENCE_CBOR_INVALID")
        val (offset, size) =
            when (raw[0].toInt() and 0xff) {
                in 0x60..0x77 -> 1 to ((raw[0].toInt() and 0xff) - 0x60)
                0x78 -> 2 to (raw.getOrNull(1)?.toUByte()?.toInt() ?: -1)
                0x79 ->
                    3 to
                        (((raw.getOrNull(1)?.toUByte()?.toInt() ?: -1) shl 8) or
                            (raw.getOrNull(2)?.toUByte()?.toInt() ?: -1))
                0x7a ->
                    5 to
                        (1..4).fold(0) { size, index ->
                            (size shl 8) or (raw.getOrNull(index)?.toUByte()?.toInt() ?: -1)
                        }
                else -> throw HostCliException("EVIDENCE_CBOR_INVALID")
            }
        if (size < 0 || raw.size != offset + size) {
            throw HostCliException("EVIDENCE_CBOR_INVALID")
        }
        return raw.copyOfRange(offset, raw.size).toString(Charsets.UTF_8)
    }
}
