package org.matrix.TEESimulator.rka.identity

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object Der {
    fun aaid(packages: List<RawPackageIdentity>, signers: List<Bytes>): ByteArray =
        item(
            0x30,
            set(
                *packages
                    .map {
                        item(
                            0x30,
                            item(0x04, it.name.toByteArray(StandardCharsets.UTF_8)) +
                                integer(it.version),
                        )
                    }
                    .toTypedArray()
            ) +
                set(
                    *signers
                        .map { item(0x04, MessageDigest.getInstance("SHA-256").digest(it.copy())) }
                        .toTypedArray()
                ),
        )

    private fun set(vararg values: ByteArray) =
        item(
            0x31,
            values
                .sortedWith(CandidateIdentityCanonicalizer::compare)
                .fold(ByteArray(0), ByteArray::plus),
        )

    private fun integer(value: ULong): ByteArray {
        val raw = ByteArray(8) { shift -> (value shr ((7 - shift) * 8)).toByte() }
        val first = raw.indexOfFirst { it != 0.toByte() }.let { if (it < 0) 7 else it }
        var body = raw.copyOfRange(first, 8)
        if (body[0].toInt() and 0x80 != 0) body = byteArrayOf(0) + body
        return item(0x02, body)
    }

    private fun item(tag: Int, body: ByteArray): ByteArray {
        val length =
            when {
                body.size < 128 -> byteArrayOf(body.size.toByte())
                body.size <= 0xff -> byteArrayOf(0x81.toByte(), body.size.toByte())
                body.size <= 0xffff ->
                    byteArrayOf(0x82.toByte(), (body.size shr 8).toByte(), body.size.toByte())
                else ->
                    byteArrayOf(
                        0x83.toByte(),
                        (body.size shr 16).toByte(),
                        (body.size shr 8).toByte(),
                        body.size.toByte(),
                    )
            }
        return byteArrayOf(tag.toByte()) + length + body
    }
}

internal object Cbor {
    fun uint(value: ULong) = head(0, value)

    fun bytes(value: ByteArray) = head(2, value.size.toULong()) + value

    fun text(value: String) =
        value.toByteArray(StandardCharsets.UTF_8).let { head(3, it.size.toULong()) + it }

    fun array(vararg values: ByteArray) =
        head(4, values.size.toULong()) + values.fold(ByteArray(0), ByteArray::plus)

    fun map(vararg values: Pair<ULong, ByteArray>) =
        head(5, values.size.toULong()) +
            values
                .sortedBy { it.first }
                .fold(ByteArray(0)) { out, (key, value) -> out + uint(key) + value }

    private fun head(major: Int, value: ULong): ByteArray {
        if (value < 24u) return byteArrayOf(((major shl 5) or value.toInt()).toByte())
        val count =
            when {
                value <= 0xffu -> 1
                value <= 0xffffu -> 2
                value <= 0xffff_ffffu -> 4
                else -> 8
            }
        val out = ByteArrayOutputStream()
        out.write((major shl 5) or mapOf(1 to 24, 2 to 25, 4 to 26, 8 to 27).getValue(count))
        for (shift in count - 1 downTo 0) out.write((value shr (shift * 8)).toInt() and 0xff)
        return out.toByteArray()
    }
}
