package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
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
    private val sameAppDifferentUidCaller =
        CallerIdentity(20234, "app-signing-cert", "attestation-id")
    private val differentSignerCaller =
        CallerIdentity(20234, "other-signing-cert", "attestation-id")
    private val differentAttestationCaller =
        CallerIdentity(20234, "app-signing-cert", "different-attestation-id")
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

        val changedBody = CanonicalBody.of("changed" to byteArrayOf(9))
        val tampered = request.copy(body = changedBody)
        assertFailsWith<ProtocolException.InvalidBodyHash> {
            session.donor.dispatch(tampered, pair, caller, clock.now(), donor::dispatch)
        }
        val changed = request.copy(body = changedBody, bodyHash = changedBody.sha256)
        assertRequestIdReuse {
            session.donor.dispatch(changed, pair, caller, clock.now(), donor::dispatch)
        }
        assertEquals(1, donor.counters.generate)
        session.target.forceNextSequenceForTest(ULong.MAX_VALUE)
        session.target.nextRequest(Method.GET_METADATA, body, clock.deadline())
        assertFailsWith<ProtocolException.SequenceOverflow> {
            session.target.nextRequest(Method.GET_METADATA, body, clock.deadline())
        }
    }

    @Test
    fun replayAuthorizationBindsImmutableRequestAndStableCaller() {
        val session = Session.establish(pair, nonce(1), nonce(2))
        val body = GenerateRequest("logical-key", challenge(7), caller).body()
        val request = session.target.nextRequest(Method.GENERATE, body, clock.deadline())
        var handlerExecutions = 0
        val handler = { _: Method, _: CanonicalBody, _: CallerIdentity ->
            handlerExecutions++
            byteArrayOf(4, 2)
        }

        val first = session.donor.dispatch(request, pair, caller, clock.now(), handler)
        val replay =
            session.donor.dispatch(request, pair, sameAppDifferentUidCaller, clock.now(), handler)
        assertContentEquals(first, replay)
        assertEquals(1, handlerExecutions)

        listOf(differentSignerCaller, differentAttestationCaller).forEach { changedCaller ->
            assertRequestIdReuse {
                session.donor.dispatch(request, pair, changedCaller, clock.now(), handler)
            }
        }
        listOf(
                request.copy(method = Method.GET_METADATA),
                request.copy(sequence = request.sequence + 1uL),
                request.copy(deadline = request.deadline.plusSeconds(1)),
            )
            .forEach { changedRequest ->
                assertRequestIdReuse {
                    session.donor.dispatch(changedRequest, pair, caller, clock.now(), handler)
                }
            }
        assertEquals(1, handlerExecutions)

        assertFailsWith<ProtocolException.DeadlineExceeded> {
            session.donor.dispatch(request, pair, caller, clock.afterDeadline(), handler)
        }
        assertEquals(1, handlerExecutions)
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
    fun donorAcceptsSameAppIdentityAcrossUidAndRejectsChangedSignerOrAttestation() {
        val donor = FakeDonorAdapter(pair, clock)
        val generated = donor.generate(GenerateRequest("logical-key", challenge(3), caller))

        assertEquals(
            KeyState.ACTIVE,
            donor.metadata(generated.handle, sameAppDifferentUidCaller).state,
        )
        val operation = donor.begin(generated.handle, sameAppDifferentUidCaller)
        donor.updateAad(operation, sameAppDifferentUidCaller, "aad".encodeToByteArray())
        donor.update(operation, sameAppDifferentUidCaller, "data".encodeToByteArray())

        assertFailsWith<DonorException.WrongCaller> {
            donor.metadata(generated.handle, differentSignerCaller)
        }
        assertFailsWith<DonorException.WrongCaller> {
            donor.metadata(generated.handle, differentAttestationCaller)
        }
    }

    @Test
    fun identicalUpdateChunksAreEachProcessedAndBoundIntoTheTranscript() {
        val donor = FakeDonorAdapter(pair, clock)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val input = "same-data".encodeToByteArray()
        val singleUpdate = donor.begin(key.handle, caller)
        val repeatedUpdate = donor.begin(key.handle, caller)

        assertContentEquals(ByteArray(0), donor.update(singleUpdate, caller, input))
        assertContentEquals(ByteArray(0), donor.update(repeatedUpdate, caller, input))
        assertContentEquals(ByteArray(0), donor.update(repeatedUpdate, caller, input))

        assertEquals(3, donor.counters.update)
        val singleTranscript = donor.finish(singleUpdate, caller, byteArrayOf())
        val repeatedTranscript = donor.finish(repeatedUpdate, caller, byteArrayOf())
        assertTrue(singleTranscript.isNotEmpty())
        assertTrue(repeatedTranscript.isNotEmpty())
        assertFalse(singleTranscript.contentEquals(repeatedTranscript))
    }

    @Test
    fun identicalUpdateRetriesAreRejectedAfterEveryTerminalOperationState() {
        val durable = InMemoryDonorStore()
        var donor = FakeDonorAdapter(pair, clock, durable)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val input = "same-data".encodeToByteArray()
        val finished = donor.begin(key.handle, caller)
        val aborted = donor.begin(key.handle, caller)
        val lost = donor.begin(key.handle, caller)

        listOf(finished, aborted, lost).forEach { donor.update(it, caller, input) }
        donor.finish(finished, caller, byteArrayOf())
        donor.abort(aborted, caller)
        donor = FakeDonorAdapter(pair, clock, durable)

        listOf(
                finished to OperationState.FINISHED,
                aborted to OperationState.ABORTED,
                lost to OperationState.LOST,
            )
            .forEach { (operation, expectedState) ->
                assertEquals(expectedState, donor.operationState(operation))
                assertFailsWith<DonorException.InvalidState> {
                    donor.update(operation, caller, input)
                }
            }
    }

    @Test
    fun pairScopedViewsAndTransportCallsDoNotSimulateDonorRestart() {
        val durable = InMemoryDonorStore()
        val donor = FakeDonorAdapter(pair, clock, durable)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val directViewOperation = donor.begin(key.handle, caller)

        val pairView = donor.forPresentedPair(pair)
        assertEquals(OperationState.BEGUN, donor.operationState(directViewOperation))
        pairView.update(directViewOperation, caller, "direct".encodeToByteArray())

        val metadataOperation = donor.begin(key.handle, caller)
        val transport = FakePinnedTransport(pair, donor)
        assertEquals(OperationState.BEGUN, donor.operationState(metadataOperation))
        transport.metadata(key.handle, caller)
        assertEquals(OperationState.BEGUN, donor.operationState(metadataOperation))

        val generateOperation = donor.begin(key.handle, caller)
        transport.generate(GenerateRequest("two", challenge(2), caller))
        assertEquals(OperationState.BEGUN, donor.operationState(generateOperation))
    }

    @Test
    fun deleteInvalidatesAllNonterminalOperationsBeforeKeyZeroization() {
        val donor = FakeDonorAdapter(pair, clock)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val begun = donor.begin(key.handle, caller)
        val aad = donor.begin(key.handle, caller)
        val data = donor.begin(key.handle, caller)
        donor.updateAad(aad, caller, "aad".encodeToByteArray())
        donor.update(data, caller, "data".encodeToByteArray())

        donor.delete(key.handle, caller)

        listOf(begun, aad, data).forEach { operation ->
            assertEquals(OperationState.ABORTED, donor.operationState(operation))
            assertFailsWith<DonorException.InvalidState> {
                donor.update(operation, caller, "data".encodeToByteArray())
            }
            assertFailsWith<DonorException.InvalidState> {
                donor.finish(operation, caller, byteArrayOf())
            }
        }
    }

    @Test
    fun operationHandleRejectsTamperedKeyId() {
        val donor = FakeDonorAdapter(pair, clock)
        val key = donor.generate(GenerateRequest("one", challenge(1), caller))
        val operation = donor.begin(key.handle, caller)
        val tampered = operation.copy(keyId = UUID.randomUUID())

        assertFailsWith<DonorException.CopiedHandle> {
            donor.update(tampered, caller, "data".encodeToByteArray())
        }
        assertEquals(OperationState.BEGUN, donor.operationState(operation))
    }

    @Test
    fun operationCannotCrossOriginatingPairInSharedStore() {
        val durable = InMemoryDonorStore()
        val pairA = PairIdentity("target-a", "donor-a")
        val pairB = PairIdentity("target-b", "donor-b")
        val donorA = FakeDonorAdapter(pairA, clock, durable)
        val donorB = FakeDonorAdapter(pairB, clock, durable)
        val key = donorA.generate(GenerateRequest("one", challenge(1), caller))
        val operation = donorA.begin(key.handle, caller)

        assertFailsWith<DonorException.WrongPair> {
            donorB.update(operation, caller, "data".encodeToByteArray())
        }
        assertEquals(OperationState.BEGUN, donorA.operationState(operation))
    }

    @Test
    fun operationsAreConcurrentOrderedAndProcessEveryUpdate() {
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
                            donor.update(operation, caller, index.toString().encodeToByteArray())
                            donor.update(operation, caller, index.toString().encodeToByteArray())
                            donor.finish(operation, caller, byteArrayOf())
                        }
                    }
                )
                .map { it.get() }
        pool.shutdown()
        assertEquals(32, operations.size)
        assertEquals(32, donor.counters.begin)
        assertEquals(64, donor.counters.update)
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
        for (passThrough in
            listOf(
                eligible.copy(
                    securityLevel = SecurityLevel.STRONGBOX,
                    userAuthenticationRequired = true,
                ),
                eligible.copy(securityLevel = SecurityLevel.AVF, deviceLocalSemantics = true),
                eligible.copy(attested = false, userAuthenticationRequired = true),
                eligible.copy(purpose = "not-allowed", deviceLocalSemantics = true),
                eligible.copy(caller = otherCaller, userAuthenticationRequired = true),
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

    private fun assertRequestIdReuse(block: () -> Unit) {
        assertFailsWith<ProtocolException.RequestIdReuse>(block = block)
    }
}
