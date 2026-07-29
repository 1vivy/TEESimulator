package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotSame

class TargetResponseCorrelatorTest {
    private val pair = PairIdentity("target-pinned-cert", "donor-pinned-cert")
    private val clientNonce = bytes(32, 1)
    private val serverNonce = bytes(32, 2)
    private val sessionId = deriveSessionId(pair, clientNonce, serverNonce)

    @Test
    fun registeredResponseIsAcceptedOnceAndReturnedAsDefensiveOutcome() {
        val correlator = TargetResponseCorrelator(pair, clientNonce, serverNonce)
        val request = request(uuid(1), Method.UPDATE)
        val response =
            response(
                request.requestId,
                Method.UPDATE,
                WireOutcome.Success(UpdateResultPayload(7uL, bytes(16, 3))),
            )
        correlator.register(request)

        val accepted = correlator.accept(request.requestId, response)
        val acceptedSuccess = assertIs<WireOutcome.Success>(accepted)
        val acceptedPayload = assertIs<UpdateResultPayload>(acceptedSuccess.payload)
        assertContentEquals(bytes(16, 3), acceptedPayload.output)
        assertNotSame(response.outcome, accepted)
        assertNotSame(assertIs<WireOutcome.Success>(response.outcome).payload, acceptedPayload)

        assertFailsWith<ResponseCorrelationException.DuplicateResponse> {
            correlator.accept(request.requestId, response)
        }
    }

    @Test
    fun wrongSessionIdAndMethodLeaveTheExpectedRequestPending() {
        val correlator = TargetResponseCorrelator(pair, clientNonce, serverNonce)
        val request = request(uuid(2), Method.IMPORT)
        val valid =
            response(
                request.requestId,
                Method.IMPORT,
                WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD),
            )
        correlator.register(request)

        assertFailsWith<ResponseCorrelationException.WrongSession> {
            correlator.accept(
                request.requestId,
                response(
                    request.requestId,
                    Method.IMPORT,
                    WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD),
                    session = bytes(32, 99),
                ),
            )
        }
        assertFailsWith<ResponseCorrelationException.WrongMethod> {
            correlator.accept(
                request.requestId,
                response(
                    request.requestId,
                    Method.DELETE,
                    WireOutcome.Error(WireErrorCode.INVALID_STATE),
                ),
            )
        }

        assertEquals(
            WireErrorCode.UNSUPPORTED_METHOD,
            assertIs<WireOutcome.Error>(correlator.accept(request.requestId, valid)).code,
        )
    }

    @Test
    fun wrongResponseIdConsumesNeitherPendingRequest() {
        val correlator = TargetResponseCorrelator(pair, clientNonce, serverNonce)
        val first = request(uuid(3), Method.IMPORT)
        val second = request(uuid(4), Method.DELETE)
        correlator.register(first)
        correlator.register(second)

        assertFailsWith<ResponseCorrelationException.WrongRequestId> {
            correlator.accept(
                first.requestId,
                response(
                    second.requestId,
                    second.method,
                    WireOutcome.Error(WireErrorCode.INVALID_STATE),
                ),
            )
        }

        assertIs<WireOutcome.Error>(
            correlator.accept(
                first.requestId,
                response(
                    first.requestId,
                    first.method,
                    WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD),
                ),
            )
        )
        assertIs<WireOutcome.Error>(
            correlator.accept(
                second.requestId,
                response(
                    second.requestId,
                    second.method,
                    WireOutcome.Error(WireErrorCode.INVALID_STATE),
                ),
            )
        )
    }

    @Test
    fun unsolicitedResponseAndUntrustedRegistrationAreTypedFailures() {
        val correlator = TargetResponseCorrelator(pair, clientNonce, serverNonce)
        val unsolicitedId = uuid(5)
        assertFailsWith<ResponseCorrelationException.UnsolicitedResponse> {
            correlator.accept(
                unsolicitedId,
                response(
                    unsolicitedId,
                    Method.IMPORT,
                    WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD),
                ),
            )
        }

        assertFailsWith<ResponseCorrelationException.UntrustedRequest> {
            correlator.register(
                WireRequestEnvelope(
                    ProtocolVersion.V1,
                    bytes(32, 98),
                    clientNonce,
                    serverNonce,
                    0uL,
                    uuid(6),
                    NormalizedWireCodec.payloadHash(ImportRequestPayload),
                    Method.IMPORT,
                    Instant.parse("2026-07-25T12:00:30Z"),
                    WireCallerIdentity("signer", "attestation-id"),
                    ImportRequestPayload,
                )
            )
        }
    }

    private fun request(id: UUID, method: Method): WireRequestEnvelope {
        val payload =
            when (method) {
                Method.IMPORT -> ImportRequestPayload
                Method.UPDATE ->
                    UpdateRequestPayload(
                        WireOperationHandle(uuid(20), uuid(21), bytes(32, 4)),
                        7uL,
                        bytes(4, 5),
                    )
                Method.DELETE ->
                    DeleteRequestPayload(uuid(22), WireKeyHandle(uuid(23), bytes(32, 6)))
                else -> error("test method is not modeled here")
            }
        return WireRequestEnvelope(
            ProtocolVersion.V1,
            sessionId,
            clientNonce,
            serverNonce,
            0uL,
            id,
            NormalizedWireCodec.payloadHash(payload),
            method,
            Instant.parse("2026-07-25T12:00:30Z"),
            WireCallerIdentity("signer", "attestation-id"),
            payload,
        )
    }

    private fun response(
        id: UUID,
        method: Method,
        outcome: WireOutcome,
        session: ByteArray = sessionId,
    ) = WireResponseEnvelope(ProtocolVersion.V1, session, id, method, outcome)

    private fun uuid(value: Int) = UUID(0, value.toLong())

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it + seed).toByte() }
}
