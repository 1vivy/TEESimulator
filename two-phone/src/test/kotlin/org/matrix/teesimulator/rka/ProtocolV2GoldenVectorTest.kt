package org.matrix.teesimulator.rka

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class ProtocolV2GoldenVectorTest {
    @Test
    fun canonicalHelloMatchesRustGoldenVector() {
        // Given: the frozen IDs, epoch, nonce, capabilities, and zero transcript history.
        val withoutTranscript = hello(includeTranscript = false)
        val transcript =
            sha256(
                "TEESIM-RKA-V2/FRAME\u0000".encodeToByteArray() +
                    ByteArray(32) +
                    withoutTranscript,
            )

        // When: the Kotlin reference codec emits the complete HELLO frame.
        val encoded = hello(includeTranscript = true, transcript = transcript)
        val golden = resource("/rka-v2/hello.hex").decodeHex()

        // Then: the reference bytes are identical to the production Rust vector.
        assertArrayEquals(golden, encoded)
        assertEquals(2, decodeTopLevelVersion(encoded))
    }

    @Test
    fun everyV1GoldenVectorRemainsByteImmutable() {
        // Given: the frozen pre-v2 SHA-256 manifest for every fixture-only v1 vector.
        val entries =
            resource("/rka-v2/v1-sha256.txt")
                .lineSequence()
                .filter(String::isNotBlank)
                .map { line -> line.split(" ", limit = 2) }

        // When: each current classpath resource is hashed without decoding or rewriting it.
        val observed =
            entries.associate { (expected, path) ->
                expected to sha256(requireNotNull(javaClass.getResourceAsStream("/$path")).readBytes())
            }

        // Then: every current byte sequence retains its pre-v2 digest.
        observed.forEach { (expected, digest) ->
            assertEquals(expected, digest.toHex())
        }
        assertEquals(6, observed.size)
    }

    private fun hello(
        includeTranscript: Boolean,
        transcript: ByteArray = ByteArray(32),
    ): ByteArray =
        Cbor().apply {
            map(if (includeTranscript) 8 else 7)
            uint(0)
            uint(2)
            uint(1)
            uint(1)
            uint(2)
            bytes(ByteArray(16) { 0x22 })
            uint(3)
            bytes(ByteArray(32) { 0x11 })
            uint(4)
            uint(7)
            uint(5)
            uint(0)
            uint(6)
            map(5)
            uint(0)
            uint(1)
            uint(1)
            uint(1)
            uint(2)
            bytes(ByteArray(32) { 0x33 })
            uint(3)
            bytes(ByteArray(32) { 0x44 })
            uint(4)
            uint(15)
            if (includeTranscript) {
                uint(7)
                bytes(transcript)
            }
        }.finish()

    private fun decodeTopLevelVersion(encoded: ByteArray): Int {
        require(encoded.size > 3 && encoded[0] == 0xa8.toByte() && encoded[1] == 0.toByte())
        return encoded[2].toInt()
    }

    private fun resource(path: String): String =
        requireNotNull(javaClass.getResource(path)) { "missing test resource: $path" }.readText()

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun String.decodeHex(): ByteArray =
        filterNot(Char::isWhitespace).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private class Cbor {
        private val output = ByteArrayOutputStream()

        fun uint(value: Int) {
            header(0, value)
        }

        fun bytes(value: ByteArray) {
            header(2, value.size)
            output.write(value)
        }

        fun map(size: Int) {
            header(5, size)
        }

        fun finish(): ByteArray = output.toByteArray()

        private fun header(
            major: Int,
            value: Int,
        ) {
            require(value >= 0)
            val prefix = major shl 5
            when {
                value < 24 -> output.write(prefix or value)
                value <= 0xff -> {
                    output.write(prefix or 24)
                    output.write(value)
                }
                value <= 0xffff -> {
                    output.write(prefix or 25)
                    output.write(value ushr 8)
                    output.write(value)
                }
                else -> {
                    output.write(prefix or 26)
                    output.write(value ushr 24)
                    output.write(value ushr 16)
                    output.write(value ushr 8)
                    output.write(value)
                }
            }
        }
    }
}
