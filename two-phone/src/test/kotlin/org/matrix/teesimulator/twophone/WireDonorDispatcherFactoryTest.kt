package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class WireDonorDispatcherFactoryTest {
    @Test
    fun backendFactoryReceivesTheSingleDefensiveSessionIdValidatedByDispatcher() {
        val pair = PairIdentity("target", "donor")
        val clientNonce = ByteArray(32) { it.toByte() }
        val serverNonce = ByteArray(32) { (it + 32).toByte() }
        var factoryCalls = 0
        lateinit var receivedSessionId: ByteArray
        val backend = ClosingBackend()
        val dispatcher =
            WireDonorDispatcher.create(
                pair,
                clientNonce,
                serverNonce,
                { Instant.parse("2026-07-25T12:00:00Z") },
            ) { sessionId ->
                factoryCalls += 1
                receivedSessionId = sessionId
                sessionId.fill(0)
                backend
            }
        val expected = deriveSessionId(pair, clientNonce, serverNonce)
        val request = request(pair, clientNonce, serverNonce, expected)

        assertEquals(1, factoryCalls)
        assertIs<WireOutcome.Error>(dispatcher.dispatch(request).outcome).also {
            assertEquals(WireErrorCode.UNSUPPORTED_METHOD, it.code)
        }
        assertContentEquals(ByteArray(32), receivedSessionId)
        dispatcher.close()
        assertEquals(1, backend.closeCalls)
    }

    private fun request(
        pair: PairIdentity,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        sessionId: ByteArray,
    ): WireRequestEnvelope =
        WireRequestEnvelope(
            ProtocolVersion.V1,
            sessionId,
            clientNonce,
            serverNonce,
            0uL,
            UUID.randomUUID(),
            NormalizedWireCodec.payloadHash(ImportRequestPayload),
            Method.IMPORT,
            Instant.parse("2026-07-25T12:00:30Z"),
            WireCallerIdentity("signer", "app"),
            ImportRequestPayload,
        )

    private class ClosingBackend : WireDonorBackend {
        var closeCalls = 0

        override fun generate(command: BackendGenerate): BackendGeneratedKey = error("unused")

        override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
            error("unused")

        override fun delete(command: BackendDelete) = error("unused")

        override fun begin(
            handle: WireKeyHandle,
            spec: WireOperationSpec,
            caller: WireCallerIdentity,
        ): WireOperationHandle = error("unused")

        override fun update(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray = error("unused")

        override fun finish(
            operation: WireOperationHandle,
            input: ByteArray,
            caller: WireCallerIdentity,
        ): ByteArray = error("unused")

        override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) =
            error("unused")

        override fun close() {
            closeCalls += 1
        }
    }
}
