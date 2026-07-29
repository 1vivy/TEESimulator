package org.matrix.teesimulator.twophone

import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WireDonorDispatcherTest {
    private val pair = PairIdentity("target-pinned-cert", "donor-pinned-cert")
    private val otherPair = PairIdentity("other-target", "other-donor")
    private val clientNonce = bytes(32, 3)
    private val serverNonce = bytes(32, 4)
    private val restartedClientNonce = bytes(32, 5)
    private val restartedServerNonce = bytes(32, 6)
    private val sessionId = deriveSessionId(pair, clientNonce, serverNonce)
    private val restartedSessionId =
        deriveSessionId(pair, restartedClientNonce, restartedServerNonce)
    private val caller = WireCallerIdentity("signer-sha256", "attestation-application-id")
    private val otherCaller = WireCallerIdentity("other-signer", "attestation-application-id")
    private val clock = MutableClock(Instant.parse("2026-07-25T12:00:00Z"))
    private val keySpec =
        WireKeySpec(WireKeyAlgorithm.EC, WireEcCurve.P256, WireDigest.SHA256, WireKeyPurpose.SIGN)
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)
    private val nextSequences = mutableMapOf<String, ULong>()

    @Test
    fun rejectsUntrustedSessionContextBeforeDonorAccessAndUsesTrustedResponseSession() {
        val counters = DonorCounters()
        val dispatcher = dispatcher(counters = counters)
        val payload = generatePayload(uuid(100), 10)

        val wrongSession =
            dispatcher.dispatch(request(payload, sessionId = bytes(32, 99), sequence = 0uL))
        assertError(WireErrorCode.WRONG_SESSION, wrongSession)
        assertContentEquals(sessionId, wrongSession.sessionId)
        val wrongClientNonce =
            dispatcher.dispatch(
                request(payload, clientNonce = bytes(32, 98), sessionId = sessionId, sequence = 0uL)
            )
        assertError(WireErrorCode.WRONG_SESSION, wrongClientNonce)
        assertContentEquals(sessionId, wrongClientNonce.sessionId)
        val wrongServerNonce =
            dispatcher.dispatch(
                request(payload, serverNonce = bytes(32, 97), sessionId = sessionId, sequence = 0uL)
            )
        assertError(WireErrorCode.WRONG_SESSION, wrongServerNonce)
        assertContentEquals(sessionId, wrongServerNonce.sessionId)
        assertEquals(0, counters.generate)

        success<GenerateResultPayload>(dispatcher, request(payload, sequence = 0uL))
        assertEquals(1, counters.generate)
    }

    @Test
    fun exactRequestIdReplayCachesResponseAndChangedIdentityIsRejected() {
        val counters = DonorCounters()
        val dispatcher = dispatcher(counters = counters)
        val payload = generatePayload(uuid(101), 20)
        val requestId = uuid(102)
        val deadline = clock.deadline()
        val original = request(payload, sequence = 0uL, requestId = requestId, deadline = deadline)

        val first = success<GenerateResultPayload>(dispatcher, original)
        val replay = success<GenerateResultPayload>(dispatcher, original)
        assertKeyHandle(first.handle, replay.handle)
        assertEquals(1, counters.generate)

        val changedRequests =
            listOf(
                request(
                    payload,
                    sequence = 0uL,
                    requestId = requestId,
                    deadline = deadline,
                    caller = otherCaller,
                ),
                request(
                    ImportRequestPayload,
                    sequence = 0uL,
                    requestId = requestId,
                    deadline = deadline,
                ),
                request(payload, sequence = 1uL, requestId = requestId, deadline = deadline),
                request(
                    payload,
                    sequence = 0uL,
                    requestId = requestId,
                    deadline = deadline.minusSeconds(1),
                ),
                request(
                    generatePayload(payload.generationId, 21),
                    sequence = 0uL,
                    requestId = requestId,
                    deadline = deadline,
                ),
            )
        changedRequests.forEach {
            assertError(WireErrorCode.REQUEST_ID_REUSE, dispatcher.dispatch(it))
        }
        assertEquals(1, counters.generate)

        success<GenerateResultPayload>(
            dispatcher,
            request(generatePayload(uuid(103), 22), sequence = 1uL),
        )
        assertEquals(2, counters.generate)
    }

    @Test
    fun deadlineAndSequenceValidationPrecedeDonorAndTypedErrorsConsumeSequence() {
        val counters = DonorCounters()
        val dispatcher = dispatcher(counters = counters)
        val payload = generatePayload(uuid(104), 30)

        assertError(
            WireErrorCode.DEADLINE_EXCEEDED,
            dispatcher.dispatch(
                request(payload, sequence = 0uL, deadline = clock.now().minusNanos(1))
            ),
        )
        assertError(
            WireErrorCode.DEADLINE_EXCEEDED,
            dispatcher.dispatch(
                request(
                    payload,
                    sequence = 0uL,
                    deadline = clock.now().plusSeconds(PublicProfileLimits.DEADLINE_SECONDS + 1L),
                )
            ),
        )
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(request(payload, sequence = 1uL)),
        )
        assertEquals(0, counters.generate)

        val unsupported = request(ImportRequestPayload, sequence = 0uL)
        assertError(WireErrorCode.UNSUPPORTED_METHOD, dispatcher.dispatch(unsupported))
        assertError(WireErrorCode.UNSUPPORTED_METHOD, dispatcher.dispatch(unsupported))
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(request(ImportRequestPayload, sequence = 0uL)),
        )
        val generated = success<GenerateResultPayload>(dispatcher, request(payload, sequence = 1uL))
        assertEquals(1, counters.generate)

        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(
                request(GetMetadataRequestPayload(generated.handle), sequence = 3uL)
            ),
        )
    }

    @Test
    fun payloadIntegrityAndExpiryAreCheckedBeforeExactReplayCacheReturn() {
        var now = Instant.parse("2026-07-25T12:00:00Z")
        val donorClock = MutableClock(now)
        val counters = DonorCounters()
        val dispatcher =
            WireDonorDispatcher(
                pair,
                clientNonce,
                serverNonce,
                { now },
                FakeDonorAdapter(pair, donorClock, counters = counters),
            )
        val payload = generatePayload(uuid(105), 40)
        val original =
            request(payload, sequence = 0uL, requestId = uuid(106), deadline = now.plusSeconds(30))
        success<GenerateResultPayload>(dispatcher, original)

        val badHash =
            request(
                payload,
                sequence = 0uL,
                requestId = original.requestId,
                deadline = original.deadline,
                payloadHash = original.payloadHash.copyOf().also { it[0]++ },
            )
        assertError(WireErrorCode.MALFORMED_REQUEST, dispatcher.dispatch(badHash))
        assertEquals(1, counters.generate)

        now = now.plusSeconds(31)
        assertError(WireErrorCode.DEADLINE_EXCEEDED, dispatcher.dispatch(original))
        assertEquals(1, counters.generate)
    }

    @Test
    fun requestSequenceExhaustionAndConcurrentConsumptionAreDeterministic() {
        val exhaustedCounters = DonorCounters()
        val exhausted = dispatcher(counters = exhaustedCounters)
        exhausted.forceNextSequenceForTest(ULong.MAX_VALUE)
        val last = request(ImportRequestPayload, sequence = ULong.MAX_VALUE, requestId = uuid(107))
        assertError(WireErrorCode.UNSUPPORTED_METHOD, exhausted.dispatch(last))
        assertError(WireErrorCode.UNSUPPORTED_METHOD, exhausted.dispatch(last))
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            exhausted.dispatch(
                request(ImportRequestPayload, sequence = ULong.MAX_VALUE, requestId = uuid(108))
            ),
        )
        assertEquals(0, exhaustedCounters.generate)

        val concurrentCounters = DonorCounters()
        val concurrent = dispatcher(counters = concurrentCounters)
        val requests =
            listOf(
                request(generatePayload(uuid(109), 50), sequence = 0uL),
                request(generatePayload(uuid(110), 51), sequence = 0uL),
            )
        val pool = Executors.newFixedThreadPool(2)
        val outcomes =
            pool
                .invokeAll(requests.map { request -> Callable { concurrent.dispatch(request) } })
                .map { it.get().outcome }
        pool.shutdown()

        assertEquals(1, outcomes.count { it is WireOutcome.Success })
        assertEquals(
            1,
            outcomes.count { it is WireOutcome.Error && it.code == WireErrorCode.SEQUENCE_ERROR },
        )
        assertEquals(1, concurrentCounters.generate)
    }

    @Test
    fun generateRetryAndCompleteMetadataSurviveRootAndDispatcherReconstruction() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val payload = generatePayload(generationId = uuid(1), challengeSeed = 10)
        val firstDispatcher =
            dispatcher(
                pair = pair,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )

        val first = success<GenerateResultPayload>(firstDispatcher, request(payload))
        assertEquals(1, counters.generate)
        first.handle.binding.fill(0)
        first.metadata.attestationChallenge.fill(0)
        first.metadata.publicKey.fill(0)
        first.metadata.certificateChain.single().fill(0)

        val restarted =
            dispatcher(
                pair = pair,
                clientNonce = restartedClientNonce,
                serverNonce = restartedServerNonce,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val replay =
            success<GenerateResultPayload>(
                restarted,
                request(
                    payload,
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                ),
            )
        assertEquals(1, counters.generate)
        assertKeyHandle(first.handle, replay.handle)
        assertMetadataFor(payload, KeyState.ACTIVE, replay.metadata)

        val metadata =
            success<GetMetadataResultPayload>(
                    restarted,
                    request(
                        GetMetadataRequestPayload(replay.handle),
                        clientNonce = restartedClientNonce,
                        serverNonce = restartedServerNonce,
                    ),
                )
                .metadata
        assertMetadata(replay.metadata, metadata)

        val changed =
            GenerateRequestPayload(
                payload.generationId,
                payload.logicalNameHash,
                bytes(32, 99),
                payload.keySpec,
            )
        assertError(
            WireErrorCode.REPLAY_CONFLICT,
            restarted.dispatch(
                request(
                    changed,
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                )
            ),
        )
        assertEquals(1, counters.generate)
    }

    @Test
    fun generationIdsAndInternalAliasesAreScopedByStableCallerAndPair() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val generationId = uuid(2)
        val payload = generatePayload(generationId, challengeSeed = 20)
        val firstDispatcher =
            dispatcher(
                pair = pair,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val first = success<GenerateResultPayload>(firstDispatcher, request(payload))

        val second =
            success<GenerateResultPayload>(firstDispatcher, request(payload, caller = otherCaller))
        val otherPairDispatcher =
            dispatcher(
                pair = otherPair,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val third =
            success<GenerateResultPayload>(otherPairDispatcher, request(payload, pair = otherPair))

        assertEquals(3, counters.generate)
        assertEquals(
            KeyState.ACTIVE,
            success<GetMetadataResultPayload>(
                    firstDispatcher,
                    request(GetMetadataRequestPayload(first.handle)),
                )
                .metadata
                .state,
        )
        assertEquals(
            KeyState.ACTIVE,
            success<GetMetadataResultPayload>(
                    firstDispatcher,
                    request(GetMetadataRequestPayload(second.handle), caller = otherCaller),
                )
                .metadata
                .state,
        )
        assertEquals(
            KeyState.ACTIVE,
            success<GetMetadataResultPayload>(
                    otherPairDispatcher,
                    request(GetMetadataRequestPayload(third.handle), pair = otherPair),
                )
                .metadata
                .state,
        )
    }

    @Test
    fun deleteRetrySurvivesReconstructionAndChangedReuseIsRejected() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val firstDispatcher =
            dispatcher(
                pair = pair,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val firstKey = generate(firstDispatcher, uuid(3), 30)
        val secondKey = generate(firstDispatcher, uuid(4), 31)
        val deletionId = uuid(5)
        val deletion = DeleteRequestPayload(deletionId, firstKey.handle)

        success<DeleteResultPayload>(firstDispatcher, request(deletion))
        assertEquals(1, counters.delete)

        val restarted =
            dispatcher(
                pair = pair,
                clientNonce = restartedClientNonce,
                serverNonce = restartedServerNonce,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val replay =
            success<DeleteResultPayload>(
                restarted,
                request(
                    deletion,
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                ),
            )
        assertEquals(deletionId, replay.deletionId)
        assertEquals(1, counters.delete)

        assertError(
            WireErrorCode.REPLAY_CONFLICT,
            restarted.dispatch(
                request(
                    DeleteRequestPayload(deletionId, secondKey.handle),
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                )
            ),
        )
        assertEquals(1, counters.delete)
        assertEquals(
            KeyState.DELETED,
            metadata(restarted, firstKey.handle, restartedClientNonce, restartedServerNonce).state,
        )
        assertEquals(
            KeyState.ACTIVE,
            metadata(restarted, secondKey.handle, restartedClientNonce, restartedServerNonce).state,
        )
    }

    @Test
    fun sharedStoreMetadataAndDeleteCannotPersistActiveAfterDeletion() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, clock, donorStore, counters)
        val metadataDispatcher =
            WireDonorDispatcher(pair, clientNonce, serverNonce, clock::now, root, wireStore)
        val deleteDispatcher =
            WireDonorDispatcher(
                pair,
                restartedClientNonce,
                restartedServerNonce,
                clock::now,
                root,
                wireStore,
            )
        val key = generate(metadataDispatcher, uuid(21), 35)
        val metadataRequest = request(GetMetadataRequestPayload(key.handle))
        val deleteRequest =
            request(
                DeleteRequestPayload(uuid(22), key.handle),
                clientNonce = restartedClientNonce,
                serverNonce = restartedServerNonce,
            )
        val metadataEntered = CountDownLatch(1)
        val releaseMetadata = CountDownLatch(1)
        wireStore.beforeMetadataDonorReadForTest = {
            metadataEntered.countDown()
            check(releaseMetadata.await(5, TimeUnit.SECONDS))
        }
        val pool = Executors.newFixedThreadPool(2)

        val metadataFuture = pool.submit(Callable { metadataDispatcher.dispatch(metadataRequest) })
        assertTrue(metadataEntered.await(5, TimeUnit.SECONDS))
        val deleteFuture = pool.submit(Callable { deleteDispatcher.dispatch(deleteRequest) })
        releaseMetadata.countDown()
        assertIs<WireOutcome.Success>(metadataFuture.get().outcome)
        assertIs<WireOutcome.Success>(deleteFuture.get().outcome)
        wireStore.beforeMetadataDonorReadForTest = null
        pool.shutdown()

        assertEquals(1, counters.delete)
        val finalMetadata =
            success<GetMetadataResultPayload>(
                    metadataDispatcher,
                    request(GetMetadataRequestPayload(key.handle)),
                )
                .metadata
        assertEquals(KeyState.DELETED, finalMetadata.state)
    }

    @Test
    fun beginAndUpdatesReplayPerStepButIdenticalBytesAtNewStepExecuteAgain() {
        val counters = DonorCounters()
        val dispatcher = dispatcher(counters = counters)
        val key = generate(dispatcher, uuid(6), 40)
        val operationId = uuid(7)
        val begin = BeginRequestPayload(operationId, 0uL, key.handle, operationSpec)

        val begun = success<BeginResultPayload>(dispatcher, request(begin))
        val beginReplay = success<BeginResultPayload>(dispatcher, request(begin))
        assertOperationHandle(begun.operation, beginReplay.operation)
        assertEquals(1, counters.begin)

        val changedBegin =
            BeginRequestPayload(
                operationId,
                0uL,
                WireKeyHandle(key.handle.id, key.handle.binding.copyOf().also { it[0]++ }),
                operationSpec,
            )
        assertError(WireErrorCode.REPLAY_CONFLICT, dispatcher.dispatch(request(changedBegin)))
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(
                request(BeginRequestPayload(uuid(8), 1uL, key.handle, operationSpec))
            ),
        )
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(
                request(BeginRequestPayload(uuid(9), ULong.MAX_VALUE, key.handle, operationSpec))
            ),
        )

        val input = "same-data".encodeToByteArray()
        val firstUpdate = UpdateRequestPayload(begun.operation, 1uL, input)
        val first = success<UpdateResultPayload>(dispatcher, request(firstUpdate))
        val replay = success<UpdateResultPayload>(dispatcher, request(firstUpdate))
        assertContentEquals(ByteArray(0), first.output)
        assertContentEquals(first.output, replay.output)
        assertEquals(1, counters.update)

        assertError(
            WireErrorCode.REPLAY_CONFLICT,
            dispatcher.dispatch(
                request(UpdateRequestPayload(begun.operation, 1uL, "changed".encodeToByteArray()))
            ),
        )
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(request(UpdateRequestPayload(begun.operation, 3uL, input))),
        )
        assertError(
            WireErrorCode.SEQUENCE_ERROR,
            dispatcher.dispatch(
                request(UpdateRequestPayload(begun.operation, ULong.MAX_VALUE, input))
            ),
        )

        val second =
            success<UpdateResultPayload>(
                dispatcher,
                request(UpdateRequestPayload(begun.operation, 2uL, input)),
            )
        assertContentEquals(first.output, second.output)
        assertContentEquals(ByteArray(0), second.output)
        assertEquals(2, counters.update)
    }

    @Test
    fun unsupportedUpdateAadAndTerminalOperationsReplayExactlyThenRejectLaterSteps() {
        val counters = DonorCounters()
        val dispatcher = dispatcher(counters = counters)
        val key = generate(dispatcher, uuid(10), 50)
        val unsupported = begin(dispatcher, key.handle, uuid(11))
        val aad = UpdateAadRequestPayload(unsupported.operation, 1uL, bytes(4, 51))

        assertError(WireErrorCode.UNSUPPORTED_METHOD, dispatcher.dispatch(request(aad)))
        assertError(WireErrorCode.UNSUPPORTED_METHOD, dispatcher.dispatch(request(aad)))
        assertEquals(0, counters.updateAad)
        assertEquals(1, counters.abort)
        assertError(
            WireErrorCode.REPLAY_CONFLICT,
            dispatcher.dispatch(
                request(UpdateAadRequestPayload(unsupported.operation, 1uL, bytes(4, 52)))
            ),
        )
        assertError(
            WireErrorCode.INVALID_STATE,
            dispatcher.dispatch(
                request(UpdateRequestPayload(unsupported.operation, 2uL, bytes(1, 53)))
            ),
        )

        val finishing = begin(dispatcher, key.handle, uuid(12))
        val update =
            success<UpdateResultPayload>(
                dispatcher,
                request(UpdateRequestPayload(finishing.operation, 1uL, bytes(3, 54))),
            )
        assertContentEquals(ByteArray(0), update.output)
        val finish = FinishRequestPayload(finishing.operation, 2uL, bytes(3, 55))
        val finished = success<FinishResultPayload>(dispatcher, request(finish))
        val finishReplay = success<FinishResultPayload>(dispatcher, request(finish))
        assertTrue(finished.output.isNotEmpty())
        assertContentEquals(finished.output, finishReplay.output)
        assertError(
            WireErrorCode.INVALID_STATE,
            dispatcher.dispatch(
                request(UpdateRequestPayload(finishing.operation, 3uL, bytes(1, 56)))
            ),
        )

        val aborting = begin(dispatcher, key.handle, uuid(13))
        val abort = AbortRequestPayload(aborting.operation, 1uL)
        success<AbortResultPayload>(dispatcher, request(abort))
        success<AbortResultPayload>(dispatcher, request(abort))
        assertError(
            WireErrorCode.INVALID_STATE,
            dispatcher.dispatch(
                request(FinishRequestPayload(aborting.operation, 2uL, ByteArray(0)))
            ),
        )
    }

    @Test
    fun dispatcherAndRootReconstructionNeverReviveOperationStepCaches() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val firstDispatcher =
            dispatcher(
                pair = pair,
                donorStore = donorStore,
                wireStore = wireStore,
                counters = counters,
            )
        val key = generate(firstDispatcher, uuid(13), 60)
        val begun = begin(firstDispatcher, key.handle, uuid(14))
        val update = UpdateRequestPayload(begun.operation, 1uL, bytes(5, 61))
        success<UpdateResultPayload>(firstDispatcher, request(update))
        assertEquals(1, counters.update)

        val reconstructedRoot = FakeDonorAdapter(pair, clock, donorStore, counters)
        val reconstructed =
            WireDonorDispatcher(
                pair,
                restartedClientNonce,
                restartedServerNonce,
                clock::now,
                reconstructedRoot,
                wireStore,
            )
        assertEquals(
            OperationState.LOST,
            reconstructedRoot.operationState(begun.operation.toHost()),
        )
        assertError(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            reconstructed.dispatch(
                request(
                    update,
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                )
            ),
        )
        assertError(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            reconstructed.dispatch(
                request(
                    UpdateRequestPayload(begun.operation, 2uL, bytes(5, 62)),
                    clientNonce = restartedClientNonce,
                    serverNonce = restartedServerNonce,
                )
            ),
        )
        assertEquals(1, counters.update)
    }

    @Test
    fun cachedAndLiveRequestsStillValidateCallerAndHandleBindings() {
        val dispatcher = dispatcher()
        val key = generate(dispatcher, uuid(15), 70)
        assertError(
            WireErrorCode.WRONG_CALLER,
            dispatcher.dispatch(
                request(GetMetadataRequestPayload(key.handle), caller = otherCaller)
            ),
        )
        val badKey = WireKeyHandle(key.handle.id, key.handle.binding.copyOf().also { it[0]++ })
        assertError(
            WireErrorCode.INVALID_HANDLE,
            dispatcher.dispatch(request(GetMetadataRequestPayload(badKey))),
        )

        val operationId = uuid(16)
        val beginPayload = BeginRequestPayload(operationId, 0uL, key.handle, operationSpec)
        val begun = success<BeginResultPayload>(dispatcher, request(beginPayload))
        assertError(
            WireErrorCode.WRONG_CALLER,
            dispatcher.dispatch(request(beginPayload, caller = otherCaller)),
        )
        assertError(
            WireErrorCode.WRONG_CALLER,
            dispatcher.dispatch(
                request(
                    UpdateRequestPayload(begun.operation, 1uL, bytes(3, 71)),
                    caller = otherCaller,
                )
            ),
        )
        val badOperation =
            WireOperationHandle(
                begun.operation.id,
                begun.operation.keyId,
                begun.operation.binding.copyOf().also { it[0]++ },
            )
        assertError(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            dispatcher.dispatch(request(UpdateRequestPayload(badOperation, 1uL, bytes(3, 71)))),
        )
    }

    @Test
    fun importSessionPairAndDeletedKeyFailuresUseNarrowWireErrors() {
        val donorStore = InMemoryDonorStore()
        val wireStore = InMemoryWireDonorStore()
        val counters = DonorCounters()
        val root = FakeDonorAdapter(pair, clock, donorStore, counters)
        val dispatcher =
            WireDonorDispatcher(pair, clientNonce, serverNonce, clock::now, root, wireStore)

        assertError(
            WireErrorCode.UNSUPPORTED_METHOD,
            dispatcher.dispatch(request(ImportRequestPayload)),
        )
        assertError(
            WireErrorCode.WRONG_SESSION,
            dispatcher.dispatch(
                request(ImportRequestPayload, sessionId = restartedSessionId, sequence = 0uL)
            ),
        )
        assertError(
            WireErrorCode.WRONG_PAIR,
            WireDonorDispatcher(otherPair, clientNonce, serverNonce, clock::now, root, wireStore)
                .dispatch(request(generatePayload(uuid(17), 80), pair = otherPair)),
        )

        val key = generate(dispatcher, uuid(18), 81)
        success<DeleteResultPayload>(
            dispatcher,
            request(DeleteRequestPayload(uuid(19), key.handle)),
        )
        assertError(
            WireErrorCode.INVALID_STATE,
            dispatcher.dispatch(
                request(BeginRequestPayload(uuid(20), 0uL, key.handle, operationSpec))
            ),
        )
    }

    private fun dispatcher(
        pair: PairIdentity = this.pair,
        clientNonce: ByteArray = this.clientNonce,
        serverNonce: ByteArray = this.serverNonce,
        donorStore: InMemoryDonorStore = InMemoryDonorStore(),
        wireStore: InMemoryWireDonorStore = InMemoryWireDonorStore(),
        counters: DonorCounters = DonorCounters(),
        now: () -> Instant = clock::now,
    ) =
        WireDonorDispatcher(
            pair,
            clientNonce,
            serverNonce,
            now,
            FakeDonorAdapter(pair, clock, donorStore, counters),
            wireStore,
        )

    private fun generate(dispatcher: WireDonorDispatcher, generationId: UUID, challengeSeed: Int) =
        success<GenerateResultPayload>(
            dispatcher,
            request(generatePayload(generationId, challengeSeed)),
        )

    private fun generatePayload(generationId: UUID, challengeSeed: Int) =
        GenerateRequestPayload(generationId, bytes(32, 90), bytes(32, challengeSeed), keySpec)

    private fun begin(dispatcher: WireDonorDispatcher, handle: WireKeyHandle, operationId: UUID) =
        success<BeginResultPayload>(
            dispatcher,
            request(BeginRequestPayload(operationId, 0uL, handle, operationSpec)),
        )

    private fun metadata(
        dispatcher: WireDonorDispatcher,
        handle: WireKeyHandle,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
    ) =
        success<GetMetadataResultPayload>(
                dispatcher,
                request(
                    GetMetadataRequestPayload(handle),
                    clientNonce = clientNonce,
                    serverNonce = serverNonce,
                ),
            )
            .metadata

    private fun request(
        payload: LifecycleRequestPayload,
        pair: PairIdentity = this.pair,
        clientNonce: ByteArray = this.clientNonce,
        serverNonce: ByteArray = this.serverNonce,
        sessionId: ByteArray = deriveSessionId(pair, clientNonce, serverNonce),
        sequence: ULong? = null,
        requestId: UUID = UUID.randomUUID(),
        deadline: Instant = clock.deadline(),
        caller: WireCallerIdentity = this.caller,
        payloadHash: ByteArray = NormalizedWireCodec.payloadHash(payload),
    ): WireRequestEnvelope {
        val requestSequence = sequence ?: nextSequence(sessionId)
        return WireRequestEnvelope(
            ProtocolVersion.V1,
            sessionId,
            clientNonce,
            serverNonce,
            requestSequence,
            requestId,
            payloadHash,
            payload.method,
            deadline,
            caller,
            payload,
        )
    }

    private fun nextSequence(sessionId: ByteArray): ULong {
        val key = sessionId.toHex()
        val sequence = nextSequences[key] ?: 0uL
        nextSequences[key] = sequence + 1uL
        return sequence
    }

    private inline fun <reified T : LifecycleResultPayload> success(
        dispatcher: WireDonorDispatcher,
        request: WireRequestEnvelope,
    ): T {
        val response = dispatcher.dispatch(request)
        assertContentEquals(request.sessionId, response.sessionId)
        assertEquals(request.requestId, response.requestId)
        assertEquals(request.method, response.method)
        return assertIs<T>(assertIs<WireOutcome.Success>(response.outcome).payload)
    }

    private fun assertError(expected: WireErrorCode, response: WireResponseEnvelope) {
        assertEquals(expected, assertIs<WireOutcome.Error>(response.outcome).code)
    }

    private fun assertMetadataFor(
        payload: GenerateRequestPayload,
        state: KeyState,
        metadata: WireKeyMetadata,
    ) {
        assertEquals(state, metadata.state)
        assertContentEquals(payload.challenge, metadata.attestationChallenge)
        assertEquals(payload.keySpec, metadata.keySpec)
        assertEquals(1, metadata.certificateChain.size)
    }

    private fun assertMetadata(expected: WireKeyMetadata, actual: WireKeyMetadata) {
        assertEquals(expected.state, actual.state)
        assertContentEquals(expected.attestationChallenge, actual.attestationChallenge)
        assertContentEquals(expected.publicKey, actual.publicKey)
        assertEquals(expected.certificateChain.size, actual.certificateChain.size)
        expected.certificateChain.zip(actual.certificateChain).forEach { (left, right) ->
            assertContentEquals(left, right)
        }
        assertEquals(expected.keySpec, actual.keySpec)
    }

    private fun assertKeyHandle(expected: WireKeyHandle, actual: WireKeyHandle) {
        assertEquals(expected.id, actual.id)
        assertContentEquals(expected.binding, actual.binding)
    }

    private fun assertOperationHandle(expected: WireOperationHandle, actual: WireOperationHandle) {
        assertEquals(expected.id, actual.id)
        assertEquals(expected.keyId, actual.keyId)
        assertContentEquals(expected.binding, actual.binding)
    }

    private fun WireOperationHandle.toHost() = OperationHandle(id, keyId, binding)

    private fun uuid(value: Int) = UUID(0, value.toLong())

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it + seed).toByte() }
}
