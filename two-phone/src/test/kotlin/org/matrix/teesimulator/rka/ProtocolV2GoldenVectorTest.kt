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

    @Test
    fun schemaMatrixCoversEveryFrozenBodyAndPinsBeginBytes() {
        // Given: the shared Rust/Kotlin manifest for every frozen body schema kind.
        val vectors =
            resource("/rka-v2/schema-matrix.txt")
                .lineSequence()
                .filter(String::isNotBlank)
                .map { line -> line.split(" ", limit = 2) }
                .map { (name, encoded) -> name to encoded.decodeHex() }
                .toList()
        val expectedNames =
            listOf(
                "hello",
                "hello_ack",
                "generate",
                "get",
                "list",
                "delete",
                "begin",
                "update_aad",
                "update",
                "finish",
                "abort",
                "result_generate",
                "result_get",
                "result_list",
                "result_delete",
                "result_begin",
                "result_update_aad",
                "result_update",
                "result_finish",
                "result_abort",
                "error",
            )
        val expectedKinds = listOf(1, 2, 10, 11, 12, 13, 20, 21, 22, 23, 24) + List(9) { 30 } + 31

        // When: Kotlin consumes every shared frame and independently emits frozen BEGIN.
        val observedKinds = vectors.map { (_, encoded) -> topLevelKind(encoded) }
        val beginGolden = vectors.single { (name, _) -> name == "begin" }.second

        // Then: coverage, numeric tags, and BEGIN's four-field canonical bytes are exact.
        assertEquals(expectedNames, vectors.map(Pair<String, ByteArray>::first))
        assertEquals(expectedKinds, observedKinds)
        assertArrayEquals(beginGolden, begin())
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

    private fun begin(): ByteArray =
        Cbor().apply {
            map(8)
            uint(0)
            uint(2)
            uint(1)
            uint(20)
            uint(2)
            bytes(ByteArray(16) { 0x22 })
            uint(3)
            bytes(ByteArray(32) { 0x11 })
            uint(4)
            uint(7)
            uint(5)
            uint(1)
            uint(6)
            map(4)
            uint(0)
            bytes(ByteArray(16) { 0x55 })
            uint(1)
            uint(2)
            uint(2)
            uint(4)
            uint(3)
            uint(0)
            uint(7)
            bytes(ByteArray(32))
        }.finish()

    private fun topLevelKind(encoded: ByteArray): Int {
        val cursor = ProtocolV2CborCursor(encoded)
        require(cursor.collection(5) == 8)
        require(cursor.uint() == 0 && cursor.uint() == 2)
        require(cursor.uint() == 1)
        val kind = cursor.uint()
        repeat(5) {
            cursor.uint()
            cursor.skip()
        }
        require(cursor.uint() == 7)
        cursor.skip()
        require(cursor.complete())
        return kind
    }

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
