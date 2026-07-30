package org.matrix.teesimulator.rka

internal class ProtocolV2CborCursor(
    private val encoded: ByteArray,
) {
    private var offset = 0

    fun complete(): Boolean = offset == encoded.size

    fun uint(): Int {
        val (major, value) = header()
        require(major == 0)
        return value
    }

    fun collection(expectedMajor: Int): Int {
        val (major, value) = header()
        require(major == expectedMajor)
        return value
    }

    fun skip() {
        val (major, value) = header()
        when (major) {
            0, 7 -> Unit
            2, 3 -> offset += value
            4 -> repeat(value) { skip() }
            5 -> repeat(value * 2) { skip() }
            else -> error("unsupported CBOR major type $major")
        }
        require(offset <= encoded.size)
    }

    private fun header(): Pair<Int, Int> {
        val initial = encoded[offset++].toInt() and 0xff
        val additional = initial and 0x1f
        val value =
            when (additional) {
                in 0..23 -> additional
                24 -> encoded[offset++].toInt() and 0xff
                25 -> read(2)
                26 -> read(4)
                else -> error("non-canonical test vector")
            }
        return (initial ushr 5) to value
    }

    private fun read(width: Int): Int {
        var value = 0
        repeat(width) {
            value = (value shl 8) or (encoded[offset++].toInt() and 0xff)
        }
        return value
    }
}
