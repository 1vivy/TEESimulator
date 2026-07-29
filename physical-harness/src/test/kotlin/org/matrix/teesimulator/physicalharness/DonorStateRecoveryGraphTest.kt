package org.matrix.teesimulator.physicalharness

import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import org.matrix.teesimulator.twophone.KeyState

class DonorStateRecoveryGraphTest {
    @Test
    fun donorAliasesAreCanonicalKeyBoundAndDistinctFromTheStateMacAlias() {
        val keyId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val expected = "teesim_donor_key_v1_00112233445566778899aabbccddeeff"
        assertEquals(expected, DonorKeyAliasPolicy.aliasFor(keyId))
        assertNotEquals(AndroidKeyStoreHandleMac.KEY_ALIAS, expected)
        DurableKeyRecord(
            keyId,
            testScope(),
            testBytes(32, 1),
            expected,
            KeyState.ACTIVE,
            testMetadata(),
        )

        listOf(
                "arbitrary-alias",
                "teesim_donor_key_v1_00112233445566778899AABBCCDDEEFF",
                "teesim_donor_key_v1_00112233-4455-6677-8899-aabbccddeeff",
                testAlias(2),
            )
            .forEach { unsafeAlias ->
                assertQuarantine {
                    DurableKeyRecord(
                        keyId,
                        testScope(),
                        testBytes(32, 1),
                        unsafeAlias,
                        KeyState.ACTIVE,
                        testMetadata(),
                    )
                }
            }
    }

    @Test
    fun everyKeyHasExactlyOneGenerationWithThePhaseRequiredByItsState() {
        val active = testKey(state = KeyState.ACTIVE)
        assertQuarantine { DonorStateSnapshot(1uL, listOf(active), emptyList()) }
        assertQuarantine {
            DonorStateSnapshot(
                1uL,
                listOf(active),
                listOf(testMutation(id = 1, key = active), testMutation(id = 2, key = active)),
            )
        }

        val creating = testKey(id = 2, state = KeyState.CREATING)
        validSnapshot(
            creating,
            testMutation(id = 3, phase = DurableMutationPhase.PREPARED, key = creating),
        )
        assertQuarantine {
            validSnapshot(
                active,
                testMutation(id = 4, phase = DurableMutationPhase.PREPARED, key = active),
            )
        }
        listOf(KeyState.ACTIVE, KeyState.SUPERSEDED).forEach { state ->
            val key = testKey(id = state.ordinal + 10, state = state)
            validSnapshot(key, testMutation(id = state.ordinal + 20, key = key))
        }
    }

    @Test
    fun deletePendingAndDeletedStatesHaveUnambiguousDeleteRecoveryRecords() {
        val pending = testKey(id = 30, state = KeyState.DELETE_PENDING)
        val pendingGeneration = testMutation(id = 31, key = pending)
        assertQuarantine { validSnapshot(pending, pendingGeneration) }
        validSnapshot(
            pending,
            pendingGeneration,
            testMutation(
                id = 32,
                kind = DurableMutationKind.DELETE,
                phase = DurableMutationPhase.PREPARED,
                key = pending,
            ),
        )

        val deleted = testKey(id = 40, state = KeyState.DELETED)
        val deletedGeneration = testMutation(id = 41, key = deleted)
        assertQuarantine { validSnapshot(deleted, deletedGeneration) }
        validSnapshot(
            deleted,
            deletedGeneration,
            testMutation(id = 42, kind = DurableMutationKind.DELETE, key = deleted),
            testMutation(id = 43, kind = DurableMutationKind.DELETE, key = deleted),
        )
    }

    @Test
    fun onlyOnePreparedMutationMayExistAcrossTheSnapshot() {
        val creating = testKey(id = 50, scope = testScope(50), state = KeyState.CREATING)
        val pending = testKey(id = 51, scope = testScope(51), state = KeyState.DELETE_PENDING)
        assertQuarantine {
            DonorStateSnapshot(
                1uL,
                listOf(creating, pending),
                listOf(
                    testMutation(id = 52, phase = DurableMutationPhase.PREPARED, key = creating),
                    testMutation(id = 53, key = pending),
                    testMutation(
                        id = 54,
                        kind = DurableMutationKind.DELETE,
                        phase = DurableMutationPhase.PREPARED,
                        key = pending,
                    ),
                ),
            )
        }
    }

    @Test
    fun quarantinedMutationsAndLaterCommittedDeletesRequireQuarantinedKeys() {
        val active = testKey(id = 60)
        assertQuarantine {
            validSnapshot(
                active,
                testMutation(id = 61, key = active),
                testMutation(
                    id = 62,
                    kind = DurableMutationKind.DELETE,
                    phase = DurableMutationPhase.QUARANTINED,
                    key = active,
                ),
            )
        }

        val quarantined = testKey(id = 63, state = KeyState.QUARANTINED)
        validSnapshot(
            quarantined,
            testMutation(id = 64, key = quarantined),
            testMutation(id = 65, kind = DurableMutationKind.DELETE, key = quarantined),
            testMutation(
                id = 66,
                kind = DurableMutationKind.DELETE,
                phase = DurableMutationPhase.QUARANTINED,
                key = quarantined,
            ),
        )
    }

    @Test
    fun activeOrCreatingLogicalIdentityIsUniqueButSupersededHistoryIsRetained() {
        val logicalNameHash = testBytes(32, 70)
        val active = testKey(id = 70, logicalNameHash = logicalNameHash)
        val creating =
            testKey(id = 71, logicalNameHash = logicalNameHash, state = KeyState.CREATING)
        assertQuarantine {
            DonorStateSnapshot(
                1uL,
                listOf(active, creating),
                listOf(
                    testMutation(id = 72, key = active),
                    testMutation(id = 73, phase = DurableMutationPhase.PREPARED, key = creating),
                ),
            )
        }

        val superseded =
            testKey(id = 74, logicalNameHash = logicalNameHash, state = KeyState.SUPERSEDED)
        DonorStateSnapshot(
            1uL,
            listOf(active, superseded),
            listOf(testMutation(id = 75, key = active), testMutation(id = 76, key = superseded)),
        )
    }

    @Test
    fun metadataChallengeIsConstantTimeBoundToItsGenerationIntent() {
        val key = testKey(id = 80)
        assertQuarantine {
            validSnapshot(key, testMutation(id = 81, key = key, challenge = testBytes(32, 99)))
        }
        validSnapshot(
            key,
            testMutation(id = 82, key = key, challenge = key.metadata!!.attestationChallenge),
        )
    }

    private fun validSnapshot(key: DurableKeyRecord, vararg mutations: DurableMutationRecord) =
        DonorStateSnapshot(1uL, listOf(key), mutations.toList())

    private fun assertQuarantine(block: () -> Unit) {
        val failure = assertFailsWith<DonorStateQuarantineException> { block() }
        assertGenericMessage(failure)
    }
}
