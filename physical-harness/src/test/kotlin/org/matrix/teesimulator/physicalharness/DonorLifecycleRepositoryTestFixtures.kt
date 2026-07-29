package org.matrix.teesimulator.physicalharness

import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireKeyMetadata

internal class RepositoryTestRig {
    val stateStore = FakeAuthenticatedDonorStateStore()
    val keyStore = FakeDurableAndroidKeyStore()
    val authenticator = HandleAuthenticator(TestHandleMac(testBytes(32, 111)))
    val scope = testScope(101)
    private var nextKeyId = 1_000

    fun repository(keyIdFactory: (() -> UUID)? = null) =
        DonorLifecycleRepository(
            stateStore,
            keyStore,
            authenticator,
            keyIdFactory = keyIdFactory ?: { testUuid(nextKeyId++) },
        )

    fun generateCommand(
        generationId: UUID = testUuid(200),
        logicalNameHash: ByteArray = testBytes(32, 30),
        challenge: ByteArray = testBytes(32, 40),
        payloadHash: ByteArray? = null,
    ): BackendGenerate {
        val payload = GenerateRequestPayload(generationId, logicalNameHash, challenge, testKeySpec)
        return BackendGenerate(
            generationId,
            payloadHash ?: NormalizedWireCodec.payloadHash(payload),
            logicalNameHash,
            challenge,
            testKeySpec,
            scope.caller,
        )
    }

    fun deleteCommand(
        keyId: UUID,
        deletionId: UUID = testUuid(300),
        commandScope: HandleScope = scope,
        payloadHash: ByteArray? = null,
    ): BackendDelete {
        val handle = authenticator.createKeyHandle(commandScope, keyId)
        val payload = DeleteRequestPayload(deletionId, handle)
        return BackendDelete(
            deletionId,
            payloadHash ?: NormalizedWireCodec.payloadHash(payload),
            handle,
            commandScope.caller,
        )
    }

    fun validPersistedGeneration(
        revision: ULong = 2uL,
        keyId: UUID = testUuid(700),
        generationId: UUID = testUuid(701),
        state: KeyState = KeyState.ACTIVE,
        logicalNameHash: ByteArray = testBytes(32, 70),
        challenge: ByteArray = testBytes(32, 71),
    ): DonorStateSnapshot {
        val metadata = repositoryMetadata(state, challenge, 72)
        val key =
            DurableKeyRecord(
                keyId,
                scope,
                logicalNameHash,
                DonorKeyAliasPolicy.aliasFor(keyId),
                state,
                metadata,
            )
        val payload = GenerateRequestPayload(generationId, logicalNameHash, challenge, testKeySpec)
        val generation =
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.COMMITTED,
                scope,
                generationId,
                NormalizedWireCodec.payloadHash(payload),
                keyId,
                GenerateIntent(logicalNameHash, challenge, testKeySpec),
            )
        return DonorStateSnapshot(revision, listOf(key), listOf(generation))
    }
}

internal class FakeAuthenticatedDonorStateStore : AuthenticatedDonorStateStore {
    var snapshot: DonorStateSnapshot? = null
    var loadFailure: Throwable? = null
    val failBeforeSaveAttempts = mutableSetOf<Int>()
    val failAfterSaveAttempts = mutableSetOf<Int>()
    var loadCount = 0
    var saveAttempts = 0
    val savedRevisions = mutableListOf<ULong>()

    override fun load(): DonorStateSnapshot? {
        loadCount += 1
        loadFailure?.let { throw it }
        return snapshot
    }

    override fun save(snapshot: DonorStateSnapshot) {
        saveAttempts += 1
        if (saveAttempts in failBeforeSaveAttempts) throw TestRepositoryIoFailure()
        this.snapshot = snapshot
        savedRevisions += snapshot.revision
        if (saveAttempts in failAfterSaveAttempts) throw TestRepositoryIoFailure()
    }
}

internal class FakeDurableAndroidKeyStore : DurableAndroidKeyStore {
    val entries = mutableMapOf<String, WireKeyMetadata>()
    val orphanAliases = mutableSetOf<String>()
    val inspectionOverrides = mutableMapOf<String, DurableKeyInspection>()
    val inspectionFailures = mutableMapOf<String, RuntimeException>()
    var generateFailure: RuntimeException? = null
    var deleteFailure: RuntimeException? = null
    var generatedMetadata: ((ByteArray) -> WireKeyMetadata)? = null
    var forcedDeleteOutcome: DurableDeleteOutcome? = null
    var ownedAliasCalls = 0
    var inspectCalls = 0
    var generateCalls = 0
    var deleteCalls = 0

    override fun ownedAliases(): Set<String> {
        ownedAliasCalls += 1
        return entries.keys + orphanAliases
    }

    override fun inspect(
        alias: String,
        caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
        expectedChallenge: ByteArray?,
    ): DurableKeyInspection {
        inspectCalls += 1
        inspectionFailures[alias]?.let { throw it }
        inspectionOverrides[alias]?.let {
            return it
        }
        val metadata = entries[alias] ?: return DurableKeyInspection.Absent
        if (
            expectedChallenge != null &&
                !MessageDigest.isEqual(expectedChallenge, metadata.attestationChallenge)
        ) {
            return DurableKeyInspection.Rejected
        }
        return DurableKeyInspection.Verified(metadata)
    }

    override fun generate(
        alias: String,
        challenge: ByteArray,
        caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
    ): WireKeyMetadata {
        generateCalls += 1
        generateFailure?.let { throw it }
        val metadata =
            generatedMetadata?.invoke(challenge)
                ?: repositoryMetadata(KeyState.ACTIVE, challenge, generateCalls + 80)
        entries[alias] = metadata
        return metadata
    }

    override fun deleteIfExact(
        alias: String,
        caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
        expectedMetadata: WireKeyMetadata,
    ): DurableDeleteOutcome {
        deleteCalls += 1
        deleteFailure?.let { throw it }
        forcedDeleteOutcome?.let {
            return it
        }
        val actual = entries[alias] ?: return DurableDeleteOutcome.ABSENT
        if (!testMetadataMaterialEquals(actual, expectedMetadata)) {
            return DurableDeleteOutcome.MISMATCH
        }
        entries.remove(alias)
        return DurableDeleteOutcome.DELETED
    }

    fun resetCalls() {
        ownedAliasCalls = 0
        inspectCalls = 0
        generateCalls = 0
        deleteCalls = 0
    }
}

internal fun repositoryMetadata(state: KeyState, challenge: ByteArray, seed: Int) =
    WireKeyMetadata(
        state,
        challenge,
        testBytes(65, seed),
        listOf(testBytes(96, seed + 1), testBytes(97, seed + 2)),
        testKeySpec,
    )

internal fun testMetadataMaterialEquals(left: WireKeyMetadata, right: WireKeyMetadata): Boolean =
    MessageDigest.isEqual(left.attestationChallenge, right.attestationChallenge) &&
        MessageDigest.isEqual(left.publicKey, right.publicKey) &&
        left.certificateChain.size == right.certificateChain.size &&
        left.certificateChain.zip(right.certificateChain).all { (a, b) ->
            MessageDigest.isEqual(a, b)
        } &&
        left.keySpec == right.keySpec

internal class TestRepositoryIoFailure : RuntimeException("test I/O failure")

internal class TestBackendUncertainty : RuntimeException("test backend uncertainty")
