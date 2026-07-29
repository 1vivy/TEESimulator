package org.matrix.TEESimulator.twophone

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.UUID
import android.os.RemoteException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.AbortRequestPayload
import org.matrix.teesimulator.twophone.AbortResultPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.UpdateRequestPayload
import org.matrix.teesimulator.twophone.UpdateResultPayload
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOutcome
import org.matrix.TEESimulator.interception.keystore.shim.RemoteSigningOperationBinder

class RemoteNormalizedKeyLifecycleTest {
    @Test
    fun generateBeginFragmentedUpdateAndFinishReturnVerifiableEcdsaSignature() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val lifecycle = RemoteNormalizedKeyLifecycle(manager)
            val generated =
                lifecycle.generate(
                    RemoteKeyGeneration(
                        logicalName = "selected-tee-key",
                        attestationChallenge = byteArrayOf(7, 8, 9),
                    )
                )
            val operation = lifecycle.begin(generated)
            val firstFragment = "first-".encodeToByteArray()
            val secondFragment = "second".encodeToByteArray()

            assertContentEquals(ByteArray(0), operation.update(firstFragment))
            assertContentEquals(ByteArray(0), operation.update(secondFragment))
            val signature = operation.finish(ByteArray(0))

            val publicKey =
                KeyFactory.getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(generated.metadata.publicKey))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(firstFragment)
            verifier.update(secondFragment)
            assertTrue(verifier.verify(signature))
        } finally {
            assertEquals(TargetCloseOutcome.Closed, manager.close())
            rig.stopServer()
        }
    }

    @Test
    fun beginRejectsSwappedOperationHandleAndClosesTheSession() {
        val keyId = UUID.randomUUID()
        val connection = ScriptedConnection {
            WireOutcome.Success(
                BeginResultPayload(WireOperationHandle(UUID.randomUUID(), UUID.randomUUID(), byteArrayOf(2)), 0uL)
            )
        }
        val manager = manager(connection)

        assertFailsWith<TargetSessionException.CorrelationFailure> {
            RemoteNormalizedKeyLifecycle(manager).begin(remoteKey(manager, keyId))
        }

        assertTrue(connection.closed)
    }

    @Test
    fun beginRejectsKeyFromAnotherTargetSessionBeforeDispatch() {
        val firstConnection = ScriptedConnection { error("session-swapped key must not dispatch") }
        val secondConnection = ScriptedConnection { error("session-swapped key must not dispatch") }
        val firstManager = manager(firstConnection)
        val secondManager = manager(secondConnection)

        assertFailsWith<TargetSessionException.CorrelationFailure> {
            RemoteNormalizedKeyLifecycle(secondManager).begin(remoteKey(firstManager, UUID.randomUUID()))
        }

        assertFalse(firstConnection.closed)
        assertFalse(secondConnection.closed)
    }

    @Test
    fun generateRejectsMalformedResponseAndClosesTheSession() {
        val connection = ScriptedConnection { WireOutcome.Success(UpdateResultPayload(1uL, ByteArray(0))) }
        val manager = manager(connection)

        assertFailsWith<TargetSessionException.CorrelationFailure> {
            RemoteNormalizedKeyLifecycle(manager).generate(
                RemoteKeyGeneration("selected-tee-key", byteArrayOf(7))
            )
        }

        assertTrue(connection.closed)
    }

    @Test
    fun updateTimeoutAbandonsTheOperationAndClosesTheSession() {
        val keyId = UUID.randomUUID()
        val operationId = UUID.randomUUID()
        val connection =
            ScriptedConnection { payload ->
                when (payload) {
                    is BeginRequestPayload ->
                        WireOutcome.Success(
                            BeginResultPayload(
                                WireOperationHandle(operationId, keyId, byteArrayOf(3)),
                                0uL,
                            )
                        )
                    is UpdateRequestPayload -> throw TargetSessionException.DeadlineExceeded()
                    else -> error("unexpected payload")
                }
            }
        val manager = manager(connection)
        val operation = RemoteNormalizedKeyLifecycle(manager).begin(remoteKey(manager, keyId))

        assertFailsWith<TargetSessionException.DeadlineExceeded> { operation.update(byteArrayOf(1)) }

        assertTrue(connection.closed)
    }

    @Test
    fun abortSendsTypedAbortAndReleasesTheRemoteOperation() {
        val keyId = UUID.randomUUID()
        val operationId = UUID.randomUUID()
        var aborted = false
        val connection =
            ScriptedConnection { payload ->
                when (payload) {
                    is BeginRequestPayload ->
                        WireOutcome.Success(
                            BeginResultPayload(
                                WireOperationHandle(operationId, keyId, byteArrayOf(4)),
                                0uL,
                            )
                        )
                    is AbortRequestPayload -> {
                        aborted = true
                        WireOutcome.Success(AbortResultPayload(payload.step))
                    }
                    else -> error("unexpected payload")
                }
            }
        val manager = manager(connection)
        val operation = RemoteNormalizedKeyLifecycle(manager).begin(remoteKey(manager, keyId))

        operation.abort()

        assertTrue(aborted)
        assertEquals(TargetSessionState.CONNECTED, manager.state)
        assertEquals(TargetCloseOutcome.Closed, manager.close())
    }

    @Test
    fun updateAadIsExplicitlyUnsupportedAndAbortsTheRemoteOperation() {
        val keyId = UUID.randomUUID()
        val operationId = UUID.randomUUID()
        var aborted = false
        val connection =
            ScriptedConnection { payload ->
                when (payload) {
                    is BeginRequestPayload ->
                        WireOutcome.Success(
                            BeginResultPayload(
                                WireOperationHandle(operationId, keyId, byteArrayOf(5)),
                                0uL,
                            )
                        )
                    is AbortRequestPayload -> {
                        aborted = true
                        WireOutcome.Success(AbortResultPayload(payload.step))
                    }
                    else -> error("unexpected payload")
                }
            }
        val manager = manager(connection)
        val remoteOperation = RemoteNormalizedKeyLifecycle(manager).begin(remoteKey(manager, keyId))
        val binder = RemoteSigningOperationBinder(remoteOperation, FakeOriginProcessDeathLease())

        assertFailsWith<RemoteException> { binder.updateAad(byteArrayOf(1)) }

        assertTrue(aborted)
        assertTrue(
            RemoteSigningOperationBinder::class.java.declaredMethods.any { it.name == "updateAad" }
        )
    }

    private fun manager(connection: ScriptedConnection): TargetSessionManager {
        val rig = TargetLoopbackTestRig()
        return TargetSessionManager.createForTest(
            rig.profile,
            rig.caller,
            Instant::now,
            TargetConnectionFactory { _, _ -> connection },
        )
    }

    private fun remoteKey(manager: TargetSessionManager, keyId: UUID) =
        RemoteGeneratedKey(
            manager,
            WireKeyHandle(keyId, byteArrayOf(1)),
            WireKeyMetadata(
                KeyState.ACTIVE,
                byteArrayOf(1),
                byteArrayOf(2),
                listOf(byteArrayOf(3)),
                WireKeySpec(
                    WireKeyAlgorithm.EC,
                    WireEcCurve.P256,
                    WireDigest.SHA256,
                    WireKeyPurpose.SIGN,
                ),
            ),
        )

    private class ScriptedConnection(
        private val response: (LifecycleRequestPayload) -> WireOutcome,
    ) : TargetConnection {
        override val protocol = "TLSv1.3"
        var closed = false

        override fun exchange(
            sequence: ULong,
            payload: LifecycleRequestPayload,
            caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
            deadline: Instant,
            cancellation: TargetCallCancellation,
        ): WireOutcome = response(payload)

        override fun close() {
            closed = true
        }
    }
}
