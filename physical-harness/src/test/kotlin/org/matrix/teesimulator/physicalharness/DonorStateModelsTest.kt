package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import org.matrix.teesimulator.twophone.KeyState

class DonorStateModelsTest {
    @Test
    fun recordsAndSnapshotsDefensivelyCopyEveryMutableValue() {
        val logicalNameHash = testBytes(32, 1)
        val payloadHash = testBytes(32, 2)
        val challenge = testBytes(32, 3)
        val metadata = testMetadata(seed = 3)
        val key =
            DurableKeyRecord(
                testUuid(1),
                testScope(),
                logicalNameHash,
                testAlias(1),
                KeyState.ACTIVE,
                metadata,
            )
        val intent = GenerateIntent(logicalNameHash, challenge, testKeySpec)
        val mutation =
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.COMMITTED,
                key.scope,
                testUuid(2),
                payloadHash,
                key.keyId,
                intent,
            )
        val keys = mutableListOf(key)
        val mutations = mutableListOf(mutation)
        val snapshot = DonorStateSnapshot(ULong.MAX_VALUE, keys, mutations)

        logicalNameHash.fill(0)
        payloadHash.fill(0)
        challenge.fill(0)
        metadata.attestationChallenge.fill(0)
        keys.clear()
        mutations.clear()
        snapshot.keys.single().logicalNameHash.fill(0)
        snapshot.mutations.single().payloadHash.fill(0)
        snapshot.mutations.single().generateIntent!!.challenge.fill(0)
        snapshot.keys.single().metadata!!.publicKey.fill(0)

        assertEquals(ULong.MAX_VALUE, snapshot.revision)
        assertContentEquals(testBytes(32, 1), snapshot.keys.single().logicalNameHash)
        assertContentEquals(testBytes(32, 2), snapshot.mutations.single().payloadHash)
        assertContentEquals(
            testBytes(32, 3),
            snapshot.mutations.single().generateIntent!!.challenge,
        )
        assertContentEquals(testBytes(65, 4), snapshot.keys.single().metadata!!.publicKey)
        assertNotSame(snapshot.keys, snapshot.keys)
        assertNotSame(snapshot.mutations, snapshot.mutations)
        assertNotSame(snapshot.keys.single().metadata, snapshot.keys.single().metadata)
    }

    @Test
    fun keyStateControlsMetadataPresenceAndPersistedAbsentIsForbidden() {
        assertQuarantine { testKey(state = KeyState.ABSENT, metadata = null) }
        assertQuarantine { testKey(state = KeyState.CREATING, metadata = testMetadata()) }
        listOf(KeyState.ACTIVE, KeyState.SUPERSEDED, KeyState.DELETE_PENDING, KeyState.DELETED)
            .forEach { state ->
                assertQuarantine { testKey(state = state, metadata = null) }
                testKey(state = state, metadata = testMetadata(state))
            }
        testKey(state = KeyState.QUARANTINED, metadata = null)
        testKey(state = KeyState.QUARANTINED, metadata = testMetadata(KeyState.QUARANTINED))
        assertQuarantine {
            testKey(state = KeyState.ACTIVE, metadata = testMetadata(KeyState.SUPERSEDED))
        }
    }

    @Test
    fun generationAndDeletionMutationsEnforceIntentAndPreparedCommittedStates() {
        val creating = testKey(state = KeyState.CREATING)
        val active = testKey(state = KeyState.ACTIVE)
        val pending = testKey(state = KeyState.DELETE_PENDING)
        val deleted = testKey(state = KeyState.DELETED)

        testSnapshot(
            keys = listOf(creating),
            mutations = listOf(testMutation(phase = DurableMutationPhase.PREPARED, key = creating)),
        )
        testSnapshot(keys = listOf(active), mutations = listOf(testMutation(key = active)))
        testSnapshot(
            keys = listOf(pending),
            mutations =
                listOf(
                    testMutation(id = 19, key = pending),
                    testMutation(
                        kind = DurableMutationKind.DELETE,
                        phase = DurableMutationPhase.PREPARED,
                        key = pending,
                    ),
                ),
        )
        testSnapshot(
            keys = listOf(deleted),
            mutations =
                listOf(
                    testMutation(id = 19, key = deleted),
                    testMutation(kind = DurableMutationKind.DELETE, key = deleted),
                ),
        )

        assertQuarantine {
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.PREPARED,
                creating.scope,
                testUuid(90),
                testBytes(32, 1),
                creating.keyId,
                null,
            )
        }
        assertQuarantine {
            DurableMutationRecord(
                DurableMutationKind.DELETE,
                DurableMutationPhase.PREPARED,
                pending.scope,
                testUuid(91),
                testBytes(32, 1),
                pending.keyId,
                GenerateIntent(pending.logicalNameHash, testBytes(1, 2), testKeySpec),
            )
        }
        assertQuarantine {
            testSnapshot(
                keys = listOf(active),
                mutations =
                    listOf(testMutation(phase = DurableMutationPhase.PREPARED, key = active)),
            )
        }
        assertQuarantine {
            testSnapshot(
                keys = listOf(pending),
                mutations =
                    listOf(
                        testMutation(id = 19, key = pending),
                        testMutation(kind = DurableMutationKind.DELETE, key = pending),
                    ),
            )
        }
        assertQuarantine {
            testSnapshot(keys = listOf(creating), mutations = listOf(testMutation(key = creating)))
        }
    }

    @Test
    fun snapshotsRejectDuplicateIdentitiesAliasesDanglingReferencesAndScopeMismatch() {
        val first = testKey(id = 1)
        val duplicateId = testKey(id = 1)
        assertQuarantine {
            testSnapshot(keys = listOf(first, duplicateId), mutations = emptyList())
        }
        assertQuarantine { testKey(id = 2, alias = testAlias(1)) }

        val mutation = testMutation(key = first)
        val duplicateMutation = testMutation(key = first)
        assertQuarantine {
            testSnapshot(keys = listOf(first), mutations = listOf(mutation, duplicateMutation))
        }
        val dangling = testMutation(id = 21, key = testKey(id = 3))
        assertQuarantine {
            testSnapshot(
                keys = listOf(first),
                mutations = listOf(testMutation(key = first), dangling),
            )
        }

        val wrongScope =
            DurableMutationRecord(
                mutation.kind,
                mutation.phase,
                testScope(99),
                mutation.mutationId,
                mutation.payloadHash,
                mutation.keyId,
                mutation.generateIntent,
            )
        assertQuarantine { testSnapshot(keys = listOf(first), mutations = listOf(wrongScope)) }
    }

    @Test
    fun generationIntentMustMatchTheReferencedLogicalNameAndFixedSpec() {
        val key = testKey()
        val mismatched =
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.COMMITTED,
                key.scope,
                testUuid(50),
                testBytes(32, 51),
                key.keyId,
                GenerateIntent(testBytes(32, 99), testBytes(32, 52), testKeySpec),
            )
        assertQuarantine { testSnapshot(keys = listOf(key), mutations = listOf(mismatched)) }
        assertNull(
            testMutation(kind = DurableMutationKind.DELETE, key = testKey(state = KeyState.DELETED))
                .generateIntent
        )
    }

    private fun assertQuarantine(block: () -> Unit) {
        val failure = assertFailsWith<DonorStateQuarantineException> { block() }
        assertGenericMessage(failure)
    }
}
