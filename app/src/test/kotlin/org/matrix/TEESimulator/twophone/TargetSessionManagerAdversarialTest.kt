package org.matrix.TEESimulator.twophone

import java.io.IOException
import java.time.Instant
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.ImportRequestPayload
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.PublicProfileLimits
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireOutcome

class TargetSessionManagerAdversarialTest {
    @Test
    fun nonceHelloCallerBindingAndMonotonicCorrelationUseOneTls13Session() {
        val rig = TargetLoopbackTestRig()
        val server = ScriptedTargetTlsServer(rig, TargetServerScript.VALID_TWO)
        val manager = rig.manager()
        server.start()
        try {
            repeat(2) {
                assertEquals(
                    WireErrorCode.UNSUPPORTED_METHOD,
                    assertIs<WireOutcome.Error>(manager.exchange(ImportRequestPayload)).code,
                )
            }
            assertEquals(listOf(0uL, 1uL), server.requests.map { it.sequence })
            assertTrue(
                server.requests[1].requestId.leastSignificantBits >
                    server.requests[0].requestId.leastSignificantBits
            )
            assertFalse(server.requests.first().clientNonce.all { it == 0.toByte() })
            assertContentEquals(server.requests[0].clientNonce, server.requests[1].clientNonce)
            assertContentEquals(server.requests[0].serverNonce, server.requests[1].serverNonce)
            assertTrue(server.requests.all { it.caller == rig.caller })
            assertEquals("TLSv1.3", manager.negotiatedProtocol)
            assertEquals(0, server.backendInvocations.get())
            server.assertHealthy()
        } finally {
            manager.close()
            server.close()
        }
    }

    @Test
    fun wrongSessionAndWrongRequestIdAreTypedAndNeverInvokeBackend() {
        listOf(
                TargetServerScript.WRONG_SESSION to TargetSessionException.WrongSession::class,
                TargetServerScript.WRONG_REQUEST_ID to TargetSessionException.WrongRequestId::class,
            )
            .forEach { (script, failureType) ->
                val rig = TargetLoopbackTestRig()
                val server = ScriptedTargetTlsServer(rig, script)
                val manager = rig.manager()
                server.start()
                try {
                    val failure =
                        assertFailsWith<TargetSessionException> {
                            manager.exchange(ImportRequestPayload)
                        }
                    assertEquals(failureType, failure::class)
                    assertEquals(0, server.backendInvocations.get())
                } finally {
                    manager.close()
                    server.close()
                }
            }
    }

    @Test
    fun replayedResponseIsRejectedByReplayCacheWithoutFallback() {
        val rig = TargetLoopbackTestRig()
        val server = ScriptedTargetTlsServer(rig, TargetServerScript.REPLAY_RESPONSE)
        val manager = rig.manager()
        server.start()
        try {
            assertIs<WireOutcome.Error>(manager.exchange(ImportRequestPayload))
            assertFailsWith<TargetSessionException.ReplayRejected> {
                manager.exchange(ImportRequestPayload)
            }
            assertEquals(0, server.backendInvocations.get())
        } finally {
            manager.close()
            server.close()
        }
    }

    @Test
    fun oversizedResponseIsRejectedBeforeAllocationOrFallback() {
        val rig = TargetLoopbackTestRig()
        val server = ScriptedTargetTlsServer(rig, TargetServerScript.OVERSIZED_FRAME)
        val manager = rig.manager()
        server.start()
        try {
            assertFailsWith<TargetSessionException.FramingFailure> {
                manager.exchange(ImportRequestPayload)
            }
            assertEquals(0, server.backendInvocations.get())
        } finally {
            manager.close()
            server.close()
        }
    }

    @Test
    fun perCallCancellationClosesTheBlockedTransportAndReturnsTypedFailure() {
        val rig = TargetLoopbackTestRig()
        val server = ScriptedTargetTlsServer(rig, TargetServerScript.STALL_AFTER_REQUEST)
        val manager = rig.manager()
        val cancellation = TargetCallCancellation()
        val executor = Executors.newSingleThreadExecutor()
        server.start()
        try {
            val call =
                executor.submit<WireOutcome> {
                    manager.exchange(ImportRequestPayload, cancellation = cancellation)
                }
            server.awaitRequest()
            cancellation.cancel()
            val failure = assertFailsWith<ExecutionException> { call.get(5, TimeUnit.SECONDS) }
            assertIs<TargetSessionException.Cancelled>(failure.cause)
            assertEquals(TargetSessionState.DISCONNECTED, manager.state)
            assertEquals(0, server.backendInvocations.get())
        } finally {
            executor.shutdownNow()
            manager.close()
            server.close()
        }
    }

    @Test
    fun deadlinesAndProfileBoundsFailBeforeNetworkIo() {
        val rig = TargetLoopbackTestRig()
        val manager = rig.manager()
        assertEquals(1, rig.profile.maxOperations)
        assertEquals(120, rig.profile.deadlineSeconds)
        assertEquals(PublicProfileLimits.MAX_OPERATIONS, rig.profile.maxOperations)
        assertEquals(PublicProfileLimits.DEADLINE_SECONDS, rig.profile.deadlineSeconds)

        assertFailsWith<TargetSessionException.DeadlineExceeded> {
            manager.exchange(ImportRequestPayload, Instant.now().minusSeconds(1))
        }
        assertFailsWith<TargetSessionException.InvalidDeadline> {
            manager.exchange(
                ImportRequestPayload,
                Instant.now().plusSeconds(PublicProfileLimits.DEADLINE_SECONDS + 1L),
            )
        }
        assertEquals(TargetSessionState.DISCONNECTED, manager.state)
        manager.close()
    }

    @Test
    fun failingUnderlyingCloseNeverReportsClosedAndRetriesTheSameConnection() {
        val rig = TargetLoopbackTestRig()
        val closeFailure = IOException("close failed")
        val closeAttempts = AtomicInteger()
        val connection =
            object : TargetConnection {
                override val protocol = "TLSv1.3"

                override fun exchange(
                    sequence: ULong,
                    payload: LifecycleRequestPayload,
                    caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
                    deadline: Instant,
                    cancellation: TargetCallCancellation,
                ): WireOutcome = WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD)

                override fun close() {
                    closeAttempts.incrementAndGet()
                    throw closeFailure
                }
            }
        val manager =
            TargetSessionManager.createForTest(
                rig.profile,
                rig.caller,
                Instant::now,
                TargetConnectionFactory { _, _ -> connection },
            )
        assertIs<WireOutcome.Error>(manager.exchange(ImportRequestPayload))

        repeat(2) {
            val outcome = assertIs<TargetCloseOutcome.Incomplete>(manager.close())
            assertSame(closeFailure, outcome.cause)
            assertEquals(TargetSessionState.CLOSING, manager.state)
            assertEquals("TLSv1.3", manager.negotiatedProtocol)
        }
        assertEquals(2, closeAttempts.get())
    }

    @Test
    fun holderCreatesExactlyOneProcessScopedManager() {
        val rig = TargetLoopbackTestRig()
        var loads = 0
        var creations = 0
        TargetSessionManagerHolder.resetForTest()
        try {
            val first =
                TargetSessionManagerHolder.getOrCreate(
                    profileLoader = {
                        loads++
                        rig.profile
                    },
                    managerFactory = {
                        creations++
                        rig.manager(it)
                    },
                )
            val second =
                TargetSessionManagerHolder.getOrCreate(
                    profileLoader = { error("must not reload") },
                    managerFactory = { error("must not recreate") },
                )
            assertSame(first, second)
            assertEquals(1, loads)
            assertEquals(1, creations)
        } finally {
            TargetSessionManagerHolder.close()
            TargetSessionManagerHolder.resetForTest()
        }
    }

    @Test
    fun holderRejectsFixtureOrCallerMismatchBeforeReusingBoundManager() {
        val rig = TargetLoopbackTestRig()
        val firstFixture =
            FixturePackageIdentity.create("org.example.first", 1, ByteArray(32) { 1 })
        val secondFixture =
            FixturePackageIdentity.create("org.example.second", 1, ByteArray(32) { 2 })
        val firstCaller = WireCallerIdentity("first-signer", "first-application")
        val secondCaller = WireCallerIdentity("second-signer", "second-application")
        TargetSessionManagerHolder.resetForTest()
        try {
            val first =
                TargetSessionManagerHolder.getOrCreate(firstFixture, firstCaller) { rig.manager() }

            assertFailsWith<TargetSessionException.IdentityMismatch> {
                TargetSessionManagerHolder.getOrCreate(secondFixture, firstCaller) {
                    error("mismatched fixture must not create a manager")
                }
            }
            assertFailsWith<TargetSessionException.IdentityMismatch> {
                TargetSessionManagerHolder.getOrCreate(firstFixture, secondCaller) {
                    error("mismatched caller must not create a manager")
                }
            }
            assertSame(
                first,
                TargetSessionManagerHolder.getOrCreate(firstFixture, firstCaller) {
                    error("must reuse")
                },
            )
        } finally {
            TargetSessionManagerHolder.close()
            TargetSessionManagerHolder.resetForTest()
        }
    }
}
