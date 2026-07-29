package org.matrix.TEESimulator.twophone

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.FinishRequestPayload
import org.matrix.teesimulator.twophone.FinishResultPayload
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.GenerateResultPayload
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.matrix.teesimulator.twophone.WireOutcome

class TargetSessionManagerLoopbackTest {
    @Test
    fun tls13MutualAuthenticationGeneratesAndSignsEndToEnd() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()

        try {
            val generated = assertIs<GenerateResultPayload>(success(manager.exchange(generate())))
            val begun =
                assertIs<BeginResultPayload>(
                    success(
                        manager.exchange(
                            BeginRequestPayload(
                                UUID.randomUUID(),
                                0uL,
                                generated.handle,
                                WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256),
                            )
                        )
                    )
                )

            val beforeSecondBegin = rig.backendInvocations()
            assertFailsWith<TargetSessionException.OperationLimit> {
                manager.exchange(
                    BeginRequestPayload(
                        UUID.randomUUID(),
                        0uL,
                        generated.handle,
                        WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256),
                    )
                )
            }
            assertEquals(beforeSecondBegin, rig.backendInvocations())

            val input = "real loopback sign".encodeToByteArray()
            val finished =
                assertIs<FinishResultPayload>(
                    success(manager.exchange(FinishRequestPayload(begun.operation, 1uL, input)))
                )
            val publicKey =
                KeyFactory.getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(generated.metadata.publicKey))
            assertTrue(
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(publicKey)
                    update(input)
                    verify(finished.output)
                }
            )
            assertEquals("TLSv1.3", manager.negotiatedProtocol)
            assertEquals(3, rig.backendInvocations())
            assertEquals(1, rig.backends.single().generateCalls.get())
            assertEquals(1, rig.backends.single().beginCalls.get())
            assertEquals(1, rig.backends.single().finishCalls.get())
        } finally {
            assertEquals(TargetCloseOutcome.Closed, manager.close())
            assertEquals(TargetCloseOutcome.Closed, manager.close())
            rig.stopServer()
        }
    }

    @Test
    fun failedConnectionIsNotRetriedAndTheSameManagerReconnectsOnTheNextCall() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        success(manager.exchange(generate()))
        val callsBeforeFailure = rig.backendInvocations()
        rig.stopServer()

        assertFailsWith<TargetSessionException.TransportFailure> { manager.exchange(generate()) }
        assertEquals(callsBeforeFailure, rig.backendInvocations())
        assertEquals(TargetSessionState.DISCONNECTED, manager.state)

        rig.startServer()
        try {
            val generated = assertIs<GenerateResultPayload>(success(manager.exchange(generate())))
            assertContentEquals(CHALLENGE, generated.metadata.attestationChallenge)
            assertEquals("TLSv1.3", manager.negotiatedProtocol)
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    private fun generate() =
        GenerateRequestPayload(
            UUID.randomUUID(),
            ByteArray(32) { 7 },
            CHALLENGE,
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            ),
        )

    private fun success(outcome: WireOutcome) = assertIs<WireOutcome.Success>(outcome).payload

    private companion object {
        val CHALLENGE = byteArrayOf(5, 4, 3, 2, 1)
    }
}
