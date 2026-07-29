package org.matrix.teesimulator.physicalharness

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.KeyState

class DonorStateCodecTest {
    private val mac = TestHandleMac()
    private val codec = DonorStateCodec(mac)

    @Test
    fun roundTripIsDeterministicCanonicalAndSupportsMaximumRevision() {
        val high = testKey(id = 2, scope = testScope(2))
        val low = testKey(id = 1, scope = testScope(1))
        val highMutation = testMutation(id = 22, key = high)
        val lowMutation = testMutation(id = 21, key = low)
        val unsorted =
            testSnapshot(ULong.MAX_VALUE, listOf(high, low), listOf(highMutation, lowMutation))
        val sorted =
            testSnapshot(ULong.MAX_VALUE, listOf(low, high), listOf(lowMutation, highMutation))

        val encoded = codec.encode(unsorted)
        assertContentEquals(encoded, codec.encode(sorted))
        val decoded = codec.decode(encoded)
        assertSnapshotEquals(sorted, decoded)
        assertContentEquals(encoded, codec.encode(decoded))
    }

    @Test
    fun fileEnvelopeAndMacInputUseStableBigEndianValuesAndLengthPrefixes() {
        val recording = RecordingMac()
        val encoded =
            DonorStateCodec(recording).encode(testSnapshot(revision = 0x0102030405060708uL))
        val file = ByteBuffer.wrap(encoded)

        assertEquals(0x54445331, file.int)
        assertEquals(1, file.short.toInt())
        assertEquals(0, file.short.toInt())
        assertEquals(0x0102030405060708L, file.long)
        val bodyLength = file.int
        assertEquals(encoded.size - 20 - 32, bodyLength)
        assertContentEquals(ByteArray(32), encoded.copyOfRange(encoded.size - 32, encoded.size))

        val input = ByteBuffer.wrap(recording.inputs.single())
        val domain = ByteArray(input.int).also(input::get)
        val authenticated = ByteArray(input.int).also(input::get)
        assertContentEquals("teesim-state-file-v1".encodeToByteArray(), domain)
        assertContentEquals(encoded.copyOf(encoded.size - 32), authenticated)
        assertEquals(0, input.remaining())
    }

    @Test
    fun fixedSchemaUsesExplicitStableTagsRatherThanEnumOrdinalsOrNames() {
        val creating = testKey(state = KeyState.CREATING)
        val frame =
            codec.encode(
                testSnapshot(
                    keys = listOf(creating),
                    mutations =
                        listOf(
                            testMutation(
                                kind = DurableMutationKind.GENERATE,
                                phase = DurableMutationPhase.PREPARED,
                                key = creating,
                            )
                        ),
                )
            )
        val body = ByteBuffer.wrap(frame, 20, frame.size - 52).slice()
        assertEquals(1, body.int)
        body.position(body.position() + 16)
        repeat(4) { skipString(body) }
        body.position(body.position() + 32)
        skipString(body)
        assertEquals(0x0001, body.short.toInt() and 0xffff)
        assertEquals(0, body.get().toInt())
        assertEquals(1, body.int)
        assertEquals(0x0001, body.short.toInt() and 0xffff)
        assertEquals(0x0001, body.short.toInt() and 0xffff)
    }

    @Test
    fun badMacWinsBeforeMalformedRecordParsingAndMacOutputMustBeSha256Sized() {
        val encoded = codec.encode(testSnapshot())
        val alias = testAlias(1)
        val aliasIndex = encoded.indexOfBytes(alias.encodeToByteArray())
        val stateIndex = aliasIndex + alias.length
        val malformedAndTampered = encoded.copyOf().also { it[stateIndex + 1] = 0x7f }

        assertCorruption<DonorStateCorruptionException.AuthenticationFailed> {
            codec.decode(malformedAndTampered)
        }
        listOf(31, 33).forEach { size ->
            assertCorruption<DonorStateCorruptionException.InvalidMacOutput> {
                DonorStateCodec(HandleMac { ByteArray(size) }).decode(encoded)
            }
        }
    }

    @Test
    fun rejectsTamperTruncationTrailingDataUnknownTagsAndNonzeroFlags() {
        val encoded = codec.encode(testSnapshot())
        assertCorruption<DonorStateCorruptionException.AuthenticationFailed> {
            codec.decode(encoded.mutated(20))
        }

        val signed = encoded.copyOf(encoded.size - 32)
        val truncated = signed.copyOf(signed.size - 1) + ByteArray(32)
        assertCorruption<DonorStateCorruptionException.Truncated> {
            codec.decode(resign(truncated, mac))
        }

        val withTrailingBodyByte =
            signed.copyOf().let { original ->
                val changed = original + byteArrayOf(0)
                ByteBuffer.wrap(changed).putInt(16, changed.size - 20)
                changed + ByteArray(32)
            }
        assertCorruption<DonorStateCorruptionException.TrailingData> {
            codec.decode(resign(withTrailingBodyByte, mac))
        }

        val unknownState = encoded.copyOf()
        val alias = testAlias(1)
        val aliasIndex = unknownState.indexOfBytes(alias.encodeToByteArray())
        unknownState[aliasIndex + alias.length] = 0x7f
        unknownState[aliasIndex + alias.length + 1] = 0x7f
        assertCorruption<DonorStateCorruptionException.UnknownTag> {
            codec.decode(resign(unknownState, mac))
        }

        val nonzeroFlags = encoded.copyOf().also { it[7] = 1 }
        assertCorruption<DonorStateCorruptionException.UnsupportedEnvelope> {
            codec.decode(resign(nonzeroFlags, mac))
        }
    }

    @Test
    fun rejectsMalformedUtf8AndNestedOrTotalBounds() {
        val encoded = codec.encode(testSnapshot())
        val targetIndex = encoded.indexOfBytes("target-1".encodeToByteArray())
        val malformedUtf8 =
            encoded.copyOf().also {
                it[targetIndex] = 0xc3.toByte()
                it[targetIndex + 1] = 0x28
            }
        assertCorruption<DonorStateCorruptionException.InvalidUtf8> {
            codec.decode(resign(malformedUtf8, mac))
        }

        val excessiveKeyCount = encoded.copyOf().also { ByteBuffer.wrap(it).putInt(20, 65_536) }
        assertCorruption<DonorStateCorruptionException.LimitExceeded> {
            codec.decode(resign(excessiveKeyCount, mac))
        }
        assertCorruption<DonorStateCorruptionException.LimitExceeded> {
            codec.decode(ByteArray(DonorStateCodec.MAX_FILE_BYTES + 1))
        }
        assertFailsWith<DonorStateQuarantineException> {
            GenerateIntent(testBytes(32, 1), ByteArray(129), testKeySpec)
        }
        assertFailsWith<DonorStateQuarantineException> { testKey(alias = "a".repeat(256)) }
    }

    @Test
    fun authenticatedDuplicateDanglingAndImpossibleRecordsAreQuarantined() {
        val first = testKey(id = 1)
        val second = testKey(id = 2)
        val encoded =
            codec.encode(
                testSnapshot(
                    keys = listOf(first, second),
                    mutations =
                        listOf(
                            testMutation(id = 20, key = first),
                            testMutation(id = 21, key = second),
                        ),
                )
            )
        val firstId = uuidBytes(first.keyId)
        val secondIdIndex = encoded.indexOfBytes(uuidBytes(second.keyId))
        val duplicateId = encoded.copyOf().also { firstId.copyInto(it, secondIdIndex) }
        assertQuarantine { codec.decode(resign(duplicateId, mac)) }

        val mutationFrame = codec.encode(testSnapshot())
        val mutationKeyIdIndex = mutationFrame.indexOfBytes(uuidBytes(testUuid(1)), fromIndex = 40)
        assertTrue(mutationKeyIdIndex > 0)
        val dangling =
            mutationFrame.copyOf().also { uuidBytes(testUuid(99)).copyInto(it, mutationKeyIdIndex) }
        assertQuarantine { codec.decode(resign(dangling, mac)) }

        val alias = testAlias(1)
        val aliasIndex = mutationFrame.indexOfBytes(alias.encodeToByteArray())
        val impossible =
            mutationFrame.copyOf().also {
                it[aliasIndex + alias.length] = 0
                it[aliasIndex + alias.length + 1] = 1
            }
        assertQuarantine { codec.decode(resign(impossible, mac)) }
    }

    private inline fun <reified T : DonorStateCorruptionException> assertCorruption(
        block: () -> Unit
    ) {
        val failure = assertFailsWith<DonorStateCorruptionException> { block() }
        assertIs<T>(failure)
        assertGenericMessage(failure)
    }

    private fun assertQuarantine(block: () -> Unit) {
        val failure = assertFailsWith<DonorStateQuarantineException> { block() }
        assertGenericMessage(failure)
    }

    private fun skipString(buffer: ByteBuffer) {
        val size = buffer.int
        buffer.position(buffer.position() + size)
    }

    private fun uuidBytes(id: java.util.UUID): ByteArray =
        ByteBuffer.allocate(16)
            .putLong(id.mostSignificantBits)
            .putLong(id.leastSignificantBits)
            .array()

    private class RecordingMac : HandleMac {
        val inputs = mutableListOf<ByteArray>()

        override fun sign(input: ByteArray): ByteArray {
            inputs += input.copyOf()
            return ByteArray(32)
        }
    }
}
