package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TwoPhoneFoundationTest {
    private val pair = PairIdentity("target-pinned-cert", "donor-pinned-cert")
    private val caller = CallerIdentity(10123, "app-signing-cert", "attestation-id")
    private val otherCaller = CallerIdentity(10124, "other-signing-cert", "attestation-id")
    private val clock = MutableClock(Instant.parse("2026-07-25T12:00:00Z"))

    @Test
    fun canonicalProtocolBindsSessionDirectionRequestAndBody() {
        val bodyA = CanonicalBody.of("z" to byteArrayOf(2), "a" to byteArrayOf(1))
        val bodyB = CanonicalBody.of("a" to byteArrayOf(1), "z" to byteArrayOf(2))
        assertContentEquals(bodyA.encoded, bodyB.encoded)

        val session = Session.establish(pair, nonce(1), nonce(2))
        val request = session.target.nextRequest(Method.GET_METADATA, bodyA, clock.deadline())
        assertEquals(ProtocolVersion.V1, request.version)
        assertEquals(0uL, request.sequence)
        assertEquals(16, request.requestId.bytes.size)
        assertEquals(32, request.bodyHash.size)
        assertContentEquals(bodyA.sha256, request.bodyHash)
        assertFailsWith<ProtocolException.SequenceGap> {
            session.donor.accept(request.copy(sequence = 2uL), pair, caller, clock.now())
        }
        assertFailsWith<ProtocolException.OldSession> {
            Session.establish(pair, nonce(3), nonce(4))
                .donor
                .accept(request, pair, caller, clock.now())
        }
        assertFailsWith<ProtocolException.DeadlineExceeded> {
            session.donor.accept(request, pair, caller, clock.afterDeadline())
        }
    }

    @Test
    fun replayIsIdempotentButChangedBodyAndOverflowAreRejected() {
        val session = Session.establish(pair, nonce(1), nonce(2))
        val donor = FakeDonorAdapter(pair, clock)
        val body = GenerateRequest("logical-key", challenge(7), caller).body()
        val request = session.target.nextRequest(Method.GENERATE, body, clock.deadline())

        val first = session.donor.dispatch(request, pair, caller, clock.now(), donor::dispatch)
        val replay = session.donor.dispatch(request, pair, caller, clock.now(), donor::dispatch)
        assertContentEquals(first, replay)
        assertEquals(1, donor.counters.generate)

        val changed = request.copy(body = CanonicalBody.of("changed" to byteArrayOf(9)))
        assertFailsWith<ProtocolException.RequestIdBodyMismatch> {
            session.donor.dispatch(changed, pair, caller, clock.now(), donor::dispatch)
        }
        session.target.forceNextSequenceForTest(ULong.MAX_VALUE)
        session.target.nextRequest(Method.GET_METADATA, body, clock.deadline())
        assertFailsWith<ProtocolException.SequenceOverflow> {
            session.target.nextRequest(Method.GET_METADATA, body, clock.deadline())
        }
    }

    @Test
    fun fakeDonorRetainsCustodyAndBindsChallengeCallerPairAndHandles() {
        val donor = FakeDonorAdapter(pair, clock)
        val generated = donor.generate(GenerateRequest("logical-key", challenge(3), caller))
        assertEquals(KeyState.ACTIVE, donor.metadata(generated.handle, caller).state)
        assertContentEquals(challenge(3), generated.attestationChallenge)
        assertFalse(generated.toString().contains("alias", ignoreCase = true))
        assertTrue(donor.debugTargetState().none { it.contains("PRIVATE") || it.contains("alias") })

        assertFailsWith<DonorException.WrongCaller> {
            donor.metadata(generated.handle, otherCaller)
        }
        assertFailsWith<DonorException.WrongPair> {
            donor
                .forPresentedPair(PairIdentity("copied-target", pair.donorPin))
                .metadata(generated.handle, caller)
        }
        val copied = KeyHandle(generated.handle.id, generated.handle.binding.copyOf())
        copied.binding[0] = (copied.binding[0].toInt() xor 1).toByte()
        assertFailsWith<DonorException.CopiedHandle> { donor.metadata(copied, caller) }
    }

    @Test
    fun operationsAreConcurrentOrderedAndDuplicateUpdateIsIdempotent() {
        val donor = FakeDonorAdapter(pair, clock)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val pool = Executors.newFixedThreadPool(8)
        val operations =
            pool
                .invokeAll(
                    (0 until 32).map { index ->
                        Callable {
                            val operation = donor.begin(key.handle, caller)
                            donor.updateAad(operation, caller, "aad".encodeToByteArray())
                            val first =
                                donor.update(
                                    operation,
                                    caller,
                                    index.toString().encodeToByteArray(),
                                )
                            val duplicate =
                                donor.update(
                                    operation,
                                    caller,
                                    index.toString().encodeToByteArray(),
                                )
                            assertContentEquals(first, duplicate)
                            donor.finish(operation, caller, byteArrayOf())
                        }
                    }
                )
                .map { it.get() }
        pool.shutdown()
        assertEquals(32, operations.size)
        assertEquals(32, donor.counters.begin)
        assertEquals(32, donor.counters.update)
        assertTrue(donor.operationStates().values.all { it == OperationState.FINISHED })
    }

    @Test
    fun restartReconciliationAliasReplacementAndDeleteAreExplicit() {
        val durable = InMemoryDonorStore()
        var donor = FakeDonorAdapter(pair, clock, durable)
        val old = donor.generate(GenerateRequest("logical", challenge(1), caller))
        val activeOperation = donor.begin(old.handle, caller)
        donor = FakeDonorAdapter(pair, clock, durable)
        assertEquals(OperationState.LOST, donor.operationState(activeOperation))

        val replacement = donor.generate(GenerateRequest("logical", challenge(2), caller))
        assertEquals(KeyState.SUPERSEDED, donor.metadata(old.handle, caller).state)
        assertEquals(KeyState.ACTIVE, donor.metadata(replacement.handle, caller).state)
        donor.delete(replacement.handle, caller)
        assertEquals(KeyState.DELETED, donor.metadata(replacement.handle, caller).state)

        val targetStore = InMemoryTargetStore()
        var target = TargetCoordinator(pair, caller, donor, targetStore)
        target.reconcile()
        target = TargetCoordinator(pair, caller, donor, targetStore)
        assertEquals(KeyState.DELETED, target.stateOf(replacement.handle))
    }

    @Test
    fun routingIsDefaultOnlyAllowlistedFailClosedAndRejectsLocalSemantics() {
        val donor = FakeDonorAdapter(pair, clock)
        val transport = FakePinnedTransport(pair, donor)
        val policy = RoutingPolicy(setOf(caller.uid), setOf("allowed-purpose"))
        val seam = KeyMintSecurityLevelRoutingSeam(policy, transport)
        val eligible = RouteRequest.trustedAttested(caller, "allowed-purpose", challenge(9))

        assertEquals(RouteDecision.REMOTE, seam.decide(eligible))
        seam.generate(eligible, "logical")
        assertEquals(1, donor.counters.generate)

        for (passThrough in
            listOf(
                eligible.copy(securityLevel = SecurityLevel.STRONGBOX),
                eligible.copy(securityLevel = SecurityLevel.AVF),
                eligible.copy(attested = false),
                eligible.copy(purpose = "not-allowed"),
                eligible.copy(caller = otherCaller),
            )) {
            assertEquals(RouteDecision.PLATFORM_BYTE_FOR_BYTE, seam.decide(passThrough))
            assertContentEquals(passThrough.platformParcel, seam.platformBytes(passThrough))
        }
        assertEquals(0, donor.counters.strongBox)
        assertEquals(0, donor.counters.avf)

        assertFailsWith<RoutingException.UnsupportedLocalSemantics> {
            seam.decide(eligible.copy(userAuthenticationRequired = true))
        }
        assertFailsWith<RoutingException.UnsupportedLocalSemantics> {
            seam.decide(eligible.copy(deviceLocalSemantics = true))
        }
        transport.available = false
        assertFailsWith<RoutingException.DonorUnavailable> { seam.generate(eligible, "second") }
        assertEquals(0, seam.localFallbackCount)
    }

    @Test
    fun importIsExplicitlyUnsupportedUntilCustodyCanBeProven() {
        val donor = FakeDonorAdapter(pair, clock)
        assertFailsWith<DonorException.ImportNotSafelyModeled> {
            donor.importKey(byteArrayOf(1, 2, 3), caller)
        }
    }

    private fun nonce(value: Int) = ByteArray(32) { value.toByte() }

    private fun challenge(value: Int) = ByteArray(32) { (it + value).toByte() }
}
