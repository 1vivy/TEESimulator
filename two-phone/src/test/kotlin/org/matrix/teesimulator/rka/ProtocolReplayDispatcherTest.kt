package org.matrix.teesimulator.rka

import org.junit.Assert.assertEquals
import org.junit.Test

class ProtocolReplayDispatcherTest {
    @Test
    fun oldSessionSequenceDeadlineAndRequestCountFailClosed() {
        // Given: dispatchers bound to one epoch, session, deadline window, and 64 requests.
        val first = GoldenVectorFixtures.frame()
        val oldSessionDispatcher = dispatcher(first)
        val changedSession =
            first.copy(
                sessionId = first.sessionId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            )
        val changedEpoch = first.copy(profileEpoch = first.profileEpoch + 1u)
        val changedTransport = first.copy(transport = TransportKind.DIAGNOSTIC_USB_RELAY)
        val sequenceDispatcher = dispatcher(first)
        val deadlineDispatcher = dispatcher(first)
        val requestLimitDispatcher = dispatcher(first)

        // When: each session boundary is violated.
        val oldSession = oldSessionDispatcher.dispatch(RkaReferenceCodec.encode(changedSession))
        val oldEpoch = dispatcher(first).dispatch(RkaReferenceCodec.encode(changedEpoch))
        val transportMismatch =
            dispatcher(first).dispatch(RkaReferenceCodec.encode(changedTransport))
        val badSequence =
            sequenceDispatcher.dispatch(RkaReferenceCodec.encode(first.copy(sequence = 3u)))
        val badDeadline =
            deadlineDispatcher.dispatch(
                RkaReferenceCodec.encode(first.copy(deadlineUnixMillis = 1_800_000_120_001u))
            )
        repeat(RkaLimits.REQUESTS_PER_SESSION) { index ->
            val request =
                first.copy(
                    sequence = (index * 2 + 1).toULong(),
                    requestId = ByteArray(16).also { it[15] = index.toByte() },
                )
            assertEquals(
                ErrorCode.OK,
                requestLimitDispatcher.dispatch(RkaReferenceCodec.encode(request)).error,
            )
        }
        val requestLimit =
            requestLimitDispatcher.dispatch(
                RkaReferenceCodec.encode(
                    first.copy(sequence = 129u, requestId = ByteArray(16) { 0x7f })
                )
            )

        // Then: failures are typed and never admitted as a new backend request.
        assertEquals(ErrorCode.OLD_SESSION, oldSession.error)
        assertEquals(ErrorCode.OLD_SESSION, oldEpoch.error)
        assertEquals(ErrorCode.TRANSPORT_MISMATCH, transportMismatch.error)
        assertEquals(ErrorCode.SEQUENCE_ERROR, badSequence.error)
        assertEquals(ErrorCode.DEADLINE_EXCEEDED, badDeadline.error)
        assertEquals(ErrorCode.REQUEST_LIMIT, requestLimit.error)
        assertEquals(RkaLimits.REQUESTS_PER_SESSION, requestLimitDispatcher.backendExecutionCount)
    }

    @Test
    fun oneLiveOperationAndCumulativeInputAreEnforced() {
        // Given: one dispatcher and canonical begin/update frames.
        val first =
            GoldenVectorFixtures.frame(
                method = Method.BEGIN,
                payload = GoldenVectorFixtures.requestPayload(Method.BEGIN),
            )
        val dispatcher = dispatcher(first)

        // When: a second begin and more than 2 MiB cumulative input are attempted.
        val begin = dispatcher.dispatch(RkaReferenceCodec.encode(first))
        val secondBegin =
            dispatcher.dispatch(
                RkaReferenceCodec.encode(first.copy(sequence = 3u, requestId = requestId(1)))
            )
        val updateOne =
            dispatcher.dispatch(
                RkaReferenceCodec.encode(
                    first.copy(
                        method = Method.UPDATE,
                        sequence = 5u,
                        requestId = requestId(2),
                        payload =
                            PayloadBoundaryFixtures.updateRequest(
                                ByteArray(RkaLimits.REQUEST_CHUNK_BYTES)
                            ),
                    )
                )
            )
        val updateTwo =
            dispatcher.dispatch(
                RkaReferenceCodec.encode(
                    first.copy(
                        method = Method.UPDATE,
                        sequence = 7u,
                        requestId = requestId(3),
                        payload =
                            PayloadBoundaryFixtures.updateRequest(
                                ByteArray(RkaLimits.REQUEST_CHUNK_BYTES)
                            ),
                    )
                )
            )
        val tooMuch =
            dispatcher.dispatch(
                RkaReferenceCodec.encode(
                    first.copy(
                        method = Method.UPDATE,
                        sequence = 9u,
                        requestId = requestId(4),
                        payload = PayloadBoundaryFixtures.updateRequest(byteArrayOf(1)),
                    )
                )
            )

        // Then: the second operation and limit-plus-one input fail with typed errors.
        assertEquals(ErrorCode.OK, begin.error)
        assertEquals(ErrorCode.OPERATION_ALREADY_LIVE, secondBegin.error)
        assertEquals(ErrorCode.OK, updateOne.error)
        assertEquals(ErrorCode.OK, updateTwo.error)
        assertEquals(ErrorCode.INPUT_TOO_LARGE, tooMuch.error)
    }

    private fun dispatcher(frame: RkaFrame): ReferenceReplayDispatcher =
        ReferenceReplayDispatcher(
            activeEpoch = frame.profileEpoch,
            activeSessionId = frame.sessionId,
            activeTransport = frame.transport,
            sessionEstablishedUnixMillis = 1_800_000_000_000u,
        )

    private fun requestId(value: Int): ByteArray = ByteArray(16).also { it[15] = value.toByte() }
}
