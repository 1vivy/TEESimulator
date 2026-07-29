package org.matrix.teesimulator.physicalharness

import java.security.cert.X509Certificate
import java.util.UUID
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.DonorClientHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.GenerateResultPayload
import org.matrix.teesimulator.twophone.Method
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.ProtocolVersion
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireOutcome
import org.matrix.teesimulator.twophone.WireRequestEnvelope

class DonorRuntimeLoopbackQaTest {
    @Test
    fun realOwnerServesPinnedTlsLoopbackRequestAndStopsCleanly() {
        val rig = DonorRuntimeLoopbackQaRig()
        var client: SSLSocket? = null
        try {
            assertEquals(
                DonorRuntimeStartResult.STARTED,
                rig.owner.start(DonorRuntimeLoopbackQaRig.PROFILE_ID, rig.now()),
            )
            val connectedClient = rig.connect()
            client = connectedClient
            assertEquals("TLSv1.3", connectedClient.session.protocol)
            assertEquals(
                rig.donorPin,
                SpkiPin.from(connectedClient.session.peerCertificates.first() as X509Certificate),
            )
            val clientNonce = ByteArray(32) { index -> (index + 1).toByte() }
            DonorTransportHelloCodec.writeClient(
                connectedClient.outputStream,
                DonorClientHello(clientNonce),
            )
            val hello =
                checkNotNull(DonorTransportHelloCodec.readServer(connectedClient.inputStream))
            assertContentEquals(clientNonce, hello.clientNonce)
            val payload =
                GenerateRequestPayload(
                    DonorRuntimeLoopbackQaRig.GENERATION_ID,
                    DonorRuntimeLoopbackQaRig.LOGICAL_NAME_HASH,
                    DonorRuntimeLoopbackQaRig.CHALLENGE,
                    DonorRuntimeLoopbackQaRig.KEY_SPEC,
                )
            val requestId = UUID.fromString("10000000-0000-0000-0000-000000000001")
            val request =
                WireRequestEnvelope(
                    ProtocolVersion.V1,
                    derivedSessionId(
                        PairIdentity(rig.targetPin.toString(), rig.donorPin.toString()),
                        clientNonce,
                        hello.serverNonce,
                    ),
                    clientNonce,
                    hello.serverNonce,
                    0uL,
                    requestId,
                    NormalizedWireCodec.payloadHash(payload),
                    Method.GENERATE,
                    rig.now().plusSeconds(20),
                    rig.caller,
                    payload,
                )
            BoundedWireFrameIo.write(
                connectedClient.outputStream,
                NormalizedWireCodec.encodeRequest(request),
            )
            val response =
                NormalizedWireCodec.decodeResponse(
                    checkNotNull(BoundedWireFrameIo.read(connectedClient.inputStream))
                )
            assertEquals(ProtocolVersion.V1, response.version)
            assertEquals(Method.GENERATE, response.method)
            assertEquals(requestId, response.requestId)
            assertContentEquals(request.sessionId, response.sessionId)
            val result =
                assertIs<GenerateResultPayload>(
                    assertIs<WireOutcome.Success>(response.outcome).payload
                )
            rig.assertDeterministicResult(result)
            assertEquals(1, rig.process.backends.single().generateCalls.get())
            assertEquals(1, rig.processFactoryCalls.get())

            assertEquals(
                DonorRuntimeStopResult.STOPPED,
                rig.owner.stopUntil(System.nanoTime() + 5_000_000_000L),
            )

            assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
            assertTrue(rig.serverFactory.server.resourcesClosed)
            assertTrue(rig.serverFactory.server.acceptorTerminated)
            assertTrue(rig.serverFactory.server.workersTerminated)
            assertTrue(rig.serverFactory.server.deadlineSchedulerTerminated)
            assertEquals(0, rig.serverFactory.server.activeSessionCount)
            assertEquals(1, rig.process.backends.single().closeCalls.get())
            assertTrue(runCatching { connectedClient.inputStream.read() }.getOrDefault(-1) == -1)
        } finally {
            if (rig.owner.state != DonorRuntimeState.STOPPED) {
                runCatching { rig.owner.stopUntil(System.nanoTime() + 5_000_000_000L) }
            }
            client?.close()
        }
    }
}
