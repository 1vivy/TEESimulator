package org.matrix.teesimulator.rka

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProtocolGoldenVectorTest {
    @Test
    fun changedReplayIsConflict() {
        // Given: one request, its exact replay, and valid payload/binding fingerprint changes.
        val original = GoldenVectorFixtures.frame()
        val changed =
            readSingleVector("/rka-v1/direct/changed-replay-request.hex")
                .let(RkaReferenceCodec::decode)
        val changedBinding = original.copy(deadlineUnixMillis = original.deadlineUnixMillis - 1u)
        val dispatcher = dispatcherFor(original)

        // When: all frames reuse the authenticated epoch, session, and request ID.
        val firstResult = dispatcher.dispatch(RkaReferenceCodec.encode(original))
        val exactResult = dispatcher.dispatch(RkaReferenceCodec.encode(original))
        val payloadResult = dispatcher.dispatch(RkaReferenceCodec.encode(changed))
        val bindingResult = dispatcher.dispatch(RkaReferenceCodec.encode(changedBinding))

        // Then: exact replay returns the cached response and changed fingerprints conflict.
        assertEquals(ErrorCode.OK, firstResult.error)
        assertEquals(ErrorCode.OK, exactResult.error)
        assertArrayEquals(firstResult.response, exactResult.response)
        assertEquals(ErrorCode.REPLAY_CONFLICT, payloadResult.error)
        assertEquals(ErrorCode.REPLAY_CONFLICT, bindingResult.error)
        assertEquals(1, dispatcher.backendExecutionCount)
    }

    @Test
    fun exactReplayReturnsCachedSuccess() {
        // Given: one authenticated request executed by the donor.
        val request = GoldenVectorFixtures.frame()
        val dispatcher = dispatcherFor(request)
        val firstResult = dispatcher.dispatch(RkaReferenceCodec.encode(request))

        // When: the byte-identical authenticated request is replayed.
        val replayResult =
            dispatcher.dispatch(
                RkaReferenceCodec.encode(
                    RkaReferenceCodec.decode(RkaReferenceCodec.encode(request))
                )
            )

        // Then: the cached success is returned without a second backend execution.
        assertEquals(ErrorCode.OK, firstResult.error)
        assertEquals(ErrorCode.OK, replayResult.error)
        assertArrayEquals(firstResult.response, replayResult.response)
        assertEquals(1, dispatcher.backendExecutionCount)
    }

    @Test
    fun lifecycleVectorsAreByteIdenticalAfterRoundTrip() {
        // Given: canonical request and response vectors for both transport kinds.
        val transports =
            mapOf(
                "direct" to TransportKind.DIRECT_PINNED_TLS,
                "diagnostic" to TransportKind.DIAGNOSTIC_USB_RELAY,
            )

        // When: every vector is decoded and encoded again.
        val observed =
            transports.mapValues { (directory, transport) ->
                val expected =
                    GoldenVectorFixtures.lifecycleFrames(transport).associate { (name, frame) ->
                        name to RkaReferenceCodec.encode(frame)
                    }
                readBundle("/rka-v1/$directory/lifecycle.hex").map { (name, encoded) ->
                    assertArrayEquals(expected.getValue(name), encoded)
                    val decoded = RkaReferenceCodec.decode(encoded)
                    assertEquals(transport, decoded.transport)
                    assertArrayEquals(encoded, RkaReferenceCodec.encode(decoded))
                    name to decoded
                }
            }

        // Then: each transport has request and response coverage for all seven methods.
        observed.values.forEach { vectors ->
            assertEquals(Method.entries.size * 2, vectors.size)
            Method.entries.forEach { method ->
                assertEquals(
                    1,
                    vectors.count {
                        it.second.method == method && it.second.kind == MessageKind.REQUEST
                    },
                )
                assertEquals(
                    1,
                    vectors.count {
                        it.second.method == method && it.second.kind == MessageKind.RESPONSE
                    },
                )
            }
        }
        val directPayloads = observed.getValue("direct").map { it.second.payload }
        val diagnosticPayloads = observed.getValue("diagnostic").map { it.second.payload }
        directPayloads.zip(diagnosticPayloads).forEach { (direct, diagnostic) ->
            assertArrayEquals(direct, diagnostic)
        }
        val directPairs = observed.getValue("direct").chunked(2)
        directPairs.forEach { (request, response) ->
            assertArrayEquals(request.second.requestId, response.second.requestId)
        }
        assertEquals(
            Method.entries.size,
            directPairs.map { pair -> pair.first().second.requestId.toHexString() }.toSet().size,
        )
    }

    @Test
    fun schemaValidBoundaryVectorsRoundTripCanonically() {
        // Given: schema-valid old-session and unsigned-maximum golden vectors.
        val oldSession = readSingleVector("/rka-v1/shared/old-session-response.hex")
        val unsignedMaximum = readSingleVector("/rka-v1/shared/ulong-max-request.hex")

        // When: both vectors pass full payload-schema decoding.
        val oldSessionDecoded = RkaReferenceCodec.decode(oldSession)
        val unsignedMaximumDecoded = RkaReferenceCodec.decode(unsignedMaximum)

        // Then: their typed boundary values survive canonical byte-identical round trips.
        assertEquals(ErrorCode.OLD_SESSION, oldSessionDecoded.error)
        assertEquals(ULong.MAX_VALUE, unsignedMaximumDecoded.sequence)
        assertArrayEquals(oldSession, RkaReferenceCodec.encode(oldSessionDecoded))
        assertArrayEquals(unsignedMaximum, RkaReferenceCodec.encode(unsignedMaximumDecoded))
    }

    @Test
    fun framingBoundaryProbePreservesExactMaximum() {
        // Given: an explicitly non-canonical framing prefix and deterministic zero payload.
        val prefix = readSingleVector("/rka-v1/framing-probes/exact-max-frame-prefix.hex")
        val maximumFrame = prefix + ByteArray(RkaReferenceCodec.MAX_FRAME_SIZE - prefix.size)

        // When: the exact maximum is decoded by the framing layer only.
        val framing = RkaReferenceCodec.decodeFraming(maximumFrame)

        // Then: the 2 MiB boundary is accepted, while full method-schema decoding rejects it.
        assertEquals(
            RkaReferenceCodec.MAX_FRAME_SIZE,
            framing.payload.size + RkaReferenceCodec.HEADER_SIZE,
        )
        assertThrows(IllegalArgumentException::class.java) {
            RkaReferenceCodec.decode(maximumFrame)
        }
    }

    private fun readBundle(path: String): List<Pair<String, ByteArray>> =
        requireNotNull(javaClass.getResource(path)) { "missing golden vector bundle: $path" }
            .readText()
            .lineSequence()
            .filter(String::isNotBlank)
            .map { line ->
                val (name, hex) = line.split('=', limit = 2)
                name to hex.hexToByteArray()
            }
            .toList()

    private fun readSingleVector(path: String): ByteArray =
        requireNotNull(javaClass.getResource(path)) { "missing golden vector: $path" }
            .readText()
            .filterNot(Char::isWhitespace)
            .hexToByteArray()

    private fun dispatcherFor(frame: RkaFrame): ReferenceReplayDispatcher =
        ReferenceReplayDispatcher(
            activeEpoch = frame.profileEpoch,
            activeSessionId = frame.sessionId,
            activeTransport = frame.transport,
            sessionEstablishedUnixMillis = 1_800_000_000_000u,
        )
}
