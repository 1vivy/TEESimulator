package org.matrix.teesimulator.rka

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
        val vectors = schemaVectors()
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
        val expectedKinds =
            (listOf(1, 2, 10, 11, 12, 13, 20, 21, 22, 23, 24) + List(9) { 30 } + 31)
                .map(Int::toLong)

        // When: the independent Kotlin codec parses and re-emits all nested values and hashes.
        val verification = ProtocolV2Reference.verify(vectors)

        // Then: coverage, numeric tags, sequence continuity, and nonzero transcript links are exact.
        assertEquals(expectedNames, verification.names)
        assertEquals(expectedKinds, verification.kinds)
        assertEquals((0L..20L).toList(), verification.sequences)
        assertEquals(21, verification.transcripts.size)
        assertTrue(verification.transcripts.all { hash -> hash.any { it != 0.toByte() } })
    }

    @Test
    fun kotlinReferenceRejectsNestedBodyAndTranscriptMutations() {
        // Given: a non-HELLO/non-BEGIN RESULT vector with separate body and transcript mutations.
        val vectors = schemaVectors()
        val encoded = vectors.single { it.name == "result_update" }.bytes
        val nestedMutation = encoded.copyOf()
        val outputOffset = nestedMutation.find(byteArrayOf(0x43, 0x6f, 0x75, 0x74))
        nestedMutation[outputOffset + 3] = (nestedMutation[outputOffset + 3].toInt() xor 1).toByte()
        val transcriptMutation = encoded.copyOf()
        transcriptMutation[transcriptMutation.lastIndex] =
            (transcriptMutation.last().toInt() xor 1).toByte()

        // When: both corrupted frames cross the current Kotlin reference boundary.
        val rejected =
            listOf(nestedMutation, transcriptMutation).map { mutation ->
                val mutated =
                    vectors.map { vector ->
                        if (vector.name == "result_update") vector.copy(bytes = mutation) else vector
                    }
                runCatching { ProtocolV2Reference.verify(mutated) }.isFailure
            }

        // Then: schema and transcript corruption must both be rejected independently.
        assertEquals(listOf(true, true), rejected)
    }

    @Test
    fun kotlinReferenceRejectsNonCanonicalIntegerEncoding() {
        // Given: HELLO's canonical version value rewritten with a longer uint representation.
        val vectors = schemaVectors()
        val hello = vectors.first().bytes
        val nonCanonical = hello.copyOf(hello.size + 1)
        hello.copyInto(nonCanonical, destinationOffset = 3, startIndex = 2)
        nonCanonical[2] = 0x18
        nonCanonical[3] = 0x02

        // When: the altered frame crosses the independent deterministic-CBOR decoder.
        val rejected =
            runCatching {
                ProtocolV2Reference.verify(
                    vectors.mapIndexed { index, vector ->
                        if (index == 0) vector.copy(bytes = nonCanonical) else vector
                    },
                )
            }.isFailure

        // Then: the non-shortest encoding is rejected before schema acceptance.
        assertTrue(rejected)
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

    private fun schemaVectors(): List<ProtocolV2NamedVector> =
        resource("/rka-v2/schema-matrix.txt")
            .lineSequence()
            .filter(String::isNotBlank)
            .map { line -> line.split(" ", limit = 2) }
            .map { (name, encoded) -> ProtocolV2NamedVector(name, encoded.decodeHex()) }
            .toList()

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun String.decodeHex(): ByteArray =
        filterNot(Char::isWhitespace).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.find(pattern: ByteArray): Int =
        indices.first { start ->
            start + pattern.size <= size &&
                pattern.indices.all { index -> this[start + index] == pattern[index] }
        }

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
