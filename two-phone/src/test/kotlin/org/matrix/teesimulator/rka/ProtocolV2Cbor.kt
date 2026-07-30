package org.matrix.teesimulator.rka

import java.io.ByteArrayOutputStream

internal sealed interface ProtocolV2Value {
    data class UIntValue(val value: Long) : ProtocolV2Value

    class BytesValue(val value: ByteArray) : ProtocolV2Value {
        override fun equals(other: Any?): Boolean =
            other is BytesValue && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    data class TextValue(val value: String) : ProtocolV2Value

    data class ArrayValue(val values: List<ProtocolV2Value>) : ProtocolV2Value

    data class MapValue(val entries: List<Pair<Long, ProtocolV2Value>>) : ProtocolV2Value

    data class BooleanValue(val value: Boolean) : ProtocolV2Value
}

internal object ProtocolV2Cbor {
    fun encode(value: ProtocolV2Value): ByteArray =
        ByteArrayOutputStream().also { output -> write(output, value) }.toByteArray()

    fun parse(encoded: ByteArray): ProtocolV2Value {
        val parser = Parser(encoded)
        val value = parser.value(0)
        require(parser.complete()) { "trailing CBOR bytes" }
        require(encode(value).contentEquals(encoded)) { "non-canonical CBOR" }
        return value
    }

    private fun write(
        output: ByteArrayOutputStream,
        value: ProtocolV2Value,
    ) {
        when (value) {
            is ProtocolV2Value.UIntValue -> header(output, 0, value.value)
            is ProtocolV2Value.BytesValue -> {
                header(output, 2, value.value.size.toLong())
                output.write(value.value)
            }
            is ProtocolV2Value.TextValue -> {
                val encoded = value.value.encodeToByteArray()
                header(output, 3, encoded.size.toLong())
                output.write(encoded)
            }
            is ProtocolV2Value.ArrayValue -> {
                header(output, 4, value.values.size.toLong())
                value.values.forEach { element -> write(output, element) }
            }
            is ProtocolV2Value.MapValue -> {
                require(value.entries.zipWithNext().all { (left, right) -> left.first < right.first })
                header(output, 5, value.entries.size.toLong())
                value.entries.forEach { (key, child) ->
                    write(output, ProtocolV2Value.UIntValue(key))
                    write(output, child)
                }
            }
            is ProtocolV2Value.BooleanValue -> output.write(if (value.value) 0xf5 else 0xf4)
        }
    }

    private fun header(
        output: ByteArrayOutputStream,
        major: Int,
        value: Long,
    ) {
        require(value >= 0)
        val prefix = major shl 5
        when {
            value < 24 -> output.write(prefix or value.toInt())
            value <= 0xff -> {
                output.write(prefix or 24)
                output.write(value.toInt())
            }
            value <= 0xffff -> {
                output.write(prefix or 25)
                writeWidth(output, value, 2)
            }
            value <= 0xffff_ffffL -> {
                output.write(prefix or 26)
                writeWidth(output, value, 4)
            }
            else -> {
                output.write(prefix or 27)
                writeWidth(output, value, 8)
            }
        }
    }

    private fun writeWidth(
        output: ByteArrayOutputStream,
        value: Long,
        width: Int,
    ) {
        repeat(width) { index ->
            output.write((value ushr (8 * (width - index - 1))).toInt() and 0xff)
        }
    }

    private class Parser(
        private val encoded: ByteArray,
    ) {
        private var offset = 0

        fun complete(): Boolean = offset == encoded.size

        fun value(depth: Int): ProtocolV2Value {
            require(depth <= 8) { "CBOR nesting limit exceeded" }
            val initial = next()
            val major = initial ushr 5
            val additional = initial and 0x1f
            if (major == 7) {
                return when (additional) {
                    20 -> ProtocolV2Value.BooleanValue(false)
                    21 -> ProtocolV2Value.BooleanValue(true)
                    else -> error("unsupported CBOR simple value")
                }
            }
            val argument = argument(additional)
            return when (major) {
                0 -> ProtocolV2Value.UIntValue(argument)
                2 -> ProtocolV2Value.BytesValue(take(argument))
                3 -> ProtocolV2Value.TextValue(take(argument).decodeToString(throwOnInvalidSequence = true))
                4 -> ProtocolV2Value.ArrayValue(List(size(argument)) { value(depth + 1) })
                5 -> map(argument, depth)
                else -> error("unsupported CBOR major type $major")
            }
        }

        private fun map(
            count: Long,
            depth: Int,
        ): ProtocolV2Value.MapValue {
            var previous = -1L
            val entries =
                List(size(count)) {
                    val key = value(depth + 1) as? ProtocolV2Value.UIntValue
                        ?: error("map key must be unsigned")
                    require(key.value > previous) { "duplicate or unordered map key" }
                    previous = key.value
                    key.value to value(depth + 1)
                }
            return ProtocolV2Value.MapValue(entries)
        }

        private fun argument(additional: Int): Long =
            when (additional) {
                in 0..23 -> additional.toLong()
                24 -> read(1).also { require(it >= 24) { "non-shortest CBOR integer" } }
                25 -> read(2).also { require(it > 0xff) { "non-shortest CBOR integer" } }
                26 -> read(4).also { require(it > 0xffff) { "non-shortest CBOR integer" } }
                27 -> read(8).also { require(it > 0xffff_ffffL) { "non-shortest CBOR integer" } }
                else -> error("indefinite or reserved CBOR argument")
            }

        private fun read(width: Int): Long {
            var result = 0L
            repeat(width) { result = (result shl 8) or next().toLong() }
            require(result >= 0) { "unsigned CBOR value exceeds signed range" }
            return result
        }

        private fun take(length: Long): ByteArray {
            val count = size(length)
            require(offset + count <= encoded.size) { "truncated CBOR value" }
            return encoded.copyOfRange(offset, offset + count).also { offset += count }
        }

        private fun size(value: Long): Int {
            require(value <= Int.MAX_VALUE) { "CBOR value too large" }
            return value.toInt()
        }

        private fun next(): Int {
            require(offset < encoded.size) { "truncated CBOR value" }
            return encoded[offset++].toInt() and 0xff
        }
    }
}
