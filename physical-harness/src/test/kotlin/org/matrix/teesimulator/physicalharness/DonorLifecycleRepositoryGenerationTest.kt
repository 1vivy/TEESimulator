package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.KeyState

class DonorLifecycleRepositoryGenerationTest {
    @Test
    fun prepareWriteFailureHasNoKeystoreEffectAndRequiresReload() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        rig.stateStore.failBeforeSaveAttempts += 1
        val repository = rig.repository()

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, command)
        }
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(null, rig.stateStore.snapshot)

        repository.generate(rig.scope, command)
        assertEquals(2, rig.stateStore.loadCount)
        assertEquals(1, rig.keyStore.generateCalls)
        assertEquals(listOf(1uL, 2uL), rig.stateStore.savedRevisions)
    }

    @Test
    fun preparedAbsentRecoveryGeneratesExactlyOnceAndCommits() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        val keyId = testUuid(810)
        rig.stateStore.snapshot = preparedSnapshot(rig, command, keyId)

        rig.repository().recover()

        assertEquals(1, rig.keyStore.generateCalls)
        assertEquals(KeyState.ACTIVE, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(
            DurableMutationPhase.COMMITTED,
            rig.stateStore.snapshot!!.mutations.single().phase,
        )
        assertEquals(2uL, rig.stateStore.snapshot!!.revision)
    }

    @Test
    fun preparedPresentRecoveryCommitsWithoutDuplicateGeneration() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        val keyId = testUuid(811)
        val prepared = preparedSnapshot(rig, command, keyId)
        rig.stateStore.snapshot = prepared
        val alias = prepared.keys.single().internalAlias
        rig.keyStore.entries[alias] = repositoryMetadata(KeyState.ACTIVE, command.challenge, 90)

        rig.repository().recover()

        assertEquals(1, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(KeyState.ACTIVE, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(2uL, rig.stateStore.snapshot!!.revision)
    }

    @Test
    fun mismatchQuarantinesWithoutRegenerationOrDeletion() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        val keyId = testUuid(812)
        val prepared = preparedSnapshot(rig, command, keyId)
        rig.stateStore.snapshot = prepared
        rig.keyStore.entries[prepared.keys.single().internalAlias] =
            repositoryMetadata(KeyState.ACTIVE, testBytes(32, 99), 91)

        rig.repository().recover()

        assertEquals(KeyState.QUARANTINED, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(
            DurableMutationPhase.QUARANTINED,
            rig.stateStore.snapshot!!.mutations.single().phase,
        )
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun commitWriteFailureIsRecoveredFromPreparedStateWithoutCompensation() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        rig.stateStore.failBeforeSaveAttempts += 2
        val repository = rig.repository()

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, command)
        }
        assertEquals(1, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(KeyState.CREATING, rig.stateStore.snapshot!!.keys.single().state)

        rig.repository().recover()

        assertEquals(1, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(KeyState.ACTIVE, rig.stateStore.snapshot!!.keys.single().state)
    }

    @Test
    fun afterSaveAmbiguityForPreparedAndCommittedGenerationReloadsWithoutDuplicateEffect() {
        listOf(1, 2).forEach { ambiguousAttempt ->
            val rig = RepositoryTestRig()
            val repository = rig.repository()
            val command = rig.generateCommand(testUuid(270 + ambiguousAttempt))
            rig.stateStore.failAfterSaveAttempts += ambiguousAttempt

            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
                repository.generate(rig.scope, command)
            }
            repository.generate(rig.scope, command)

            assertEquals(1, rig.keyStore.generateCalls)
            assertEquals(KeyState.ACTIVE, rig.stateStore.snapshot!!.keys.single().state)
            assertEquals(
                0,
                rig.stateStore.snapshot!!.mutations.count {
                    it.phase == DurableMutationPhase.PREPARED
                },
            )
        }
    }

    @Test
    fun backendUncertaintyLeavesPreparedForLaterRecovery() {
        val rig = RepositoryTestRig()
        val command = rig.generateCommand()
        rig.stateStore.snapshot = preparedSnapshot(rig, command, testUuid(813))
        val uncertainty = TestBackendUncertainty()
        rig.keyStore.generateFailure = uncertainty

        val unavailable =
            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
                rig.repository().recover()
            }

        assertSame(uncertainty, unavailable.cause)
        assertEquals(KeyState.CREATING, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(
            DurableMutationPhase.PREPARED,
            rig.stateStore.snapshot!!.mutations.single().phase,
        )
        assertEquals(1uL, rig.stateStore.snapshot!!.revision)
    }

    @Test
    fun differentRequestReconcilesLoadedPreparedGenerationBeforePreparingAnother() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val first = rig.generateCommand(testUuid(250))
        val second = rig.generateCommand(testUuid(251), testBytes(32, 31), testBytes(32, 41))
        rig.keyStore.generateFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, first)
        }
        val savesAfterPrepare = rig.stateStore.saveAttempts

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, second)
        }
        assertEquals(savesAfterPrepare, rig.stateStore.saveAttempts)
        assertEquals(
            1,
            rig.stateStore.snapshot!!.mutations.count { it.phase == DurableMutationPhase.PREPARED },
        )

        rig.keyStore.generateFailure = null
        repository.generate(rig.scope, second)
        assertEquals(
            0,
            rig.stateStore.snapshot!!.mutations.count { it.phase == DurableMutationPhase.PREPARED },
        )
        assertEquals(
            2,
            rig.stateStore.snapshot!!.mutations.count { it.phase == DurableMutationPhase.COMMITTED },
        )
        assertEquals(listOf(1uL, 2uL, 3uL, 4uL), rig.stateStore.savedRevisions)
    }

    @Test
    fun committedReplayReturnsOriginalActiveResultAndConflictHasNoEffects() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val command = rig.generateCommand()
        val original = repository.generate(rig.scope, command)
        rig.keyStore.resetCalls()
        val saveAttempts = rig.stateStore.saveAttempts

        val replay = repository.generate(rig.scope, command)

        assertEquals(original.handle.id, replay.handle.id)
        assertEquals(KeyState.ACTIVE, replay.metadata.state)
        assertContentEquals(original.metadata.publicKey, replay.metadata.publicKey)
        assertEquals(saveAttempts, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.generateCalls)

        val conflict =
            rig.generateCommand(generationId = command.generationId, challenge = testBytes(32, 41))
        assertFailsWith<DonorLifecycleRepositoryException.ReplayConflict> {
            repository.generate(rig.scope, conflict)
        }
        assertEquals(0, rig.keyStore.generateCalls)
    }

    @Test
    fun supersessionIsMonotonicAndOldGenerationReplayRemainsActive() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val logicalName = testBytes(32, 55)
        val first = rig.generateCommand(testUuid(220), logicalName, testBytes(32, 56))
        val second = rig.generateCommand(testUuid(221), logicalName, testBytes(32, 57))
        val firstResult = repository.generate(rig.scope, first)
        repository.generate(rig.scope, second)

        val keys = rig.stateStore.snapshot!!.keys.associateBy { it.keyId }
        assertEquals(KeyState.SUPERSEDED, keys.getValue(firstResult.handle.id).state)
        assertEquals(1, keys.values.count { it.state == KeyState.ACTIVE })
        assertEquals(KeyState.ACTIVE, repository.generate(rig.scope, first).metadata.state)
        assertEquals(KeyState.SUPERSEDED, keys.getValue(firstResult.handle.id).state)
    }

    @Test
    fun maximumRevisionRejectsBeforeAnyMutationOrWrite() {
        val rig = RepositoryTestRig()
        val snapshot = rig.validPersistedGeneration(revision = ULong.MAX_VALUE)
        rig.stateStore.snapshot = snapshot
        rig.keyStore.entries[snapshot.keys.single().internalAlias] =
            snapshot.keys.single().metadata!!

        assertFailsWith<DonorLifecycleRepositoryException.RevisionExhausted> {
            rig.repository().generate(rig.scope, rig.generateCommand(testUuid(230)))
        }

        assertEquals(0, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun concurrentDuplicateGenerationSerializesToOneSideEffect() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val command = rig.generateCommand()
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        val futures =
            List(16) {
                pool.submit {
                    start.await()
                    repository.generate(rig.scope, command).handle.id
                }
            }

        start.countDown()
        val ids = futures.map { it.get(5, TimeUnit.SECONDS) }.toSet()
        pool.shutdown()

        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
        assertEquals(1, ids.size)
        assertEquals(1, rig.keyStore.generateCalls)
        assertEquals(listOf(1uL, 2uL), rig.stateStore.savedRevisions)
    }

    @Test
    fun metadataAndBeginResolutionAuthenticateHandlesAndRequireActiveState() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val logicalName = testBytes(32, 65)
        val first = rig.generateCommand(testUuid(240), logicalName, testBytes(32, 66))
        val generated = repository.generate(rig.scope, first)

        assertEquals(KeyState.ACTIVE, repository.metadata(rig.scope, generated.handle).state)
        val resolved = repository.resolveForBegin(rig.scope, generated.handle)
        assertEquals(generated.handle.id, resolved.keyId)
        assertEquals(DonorKeyAliasPolicy.aliasFor(generated.handle.id), resolved.internalAlias)

        repository.generate(
            rig.scope,
            rig.generateCommand(testUuid(241), logicalName, testBytes(32, 67)),
        )
        assertEquals(KeyState.SUPERSEDED, repository.metadata(rig.scope, generated.handle).state)
        assertEquals(
            generated.handle.id,
            repository.resolveForBegin(rig.scope, generated.handle).keyId,
        )
    }

    @Test
    fun keyIdCollisionRetriesWithoutOverwritingHistoryOrQuarantining() {
        val rig = RepositoryTestRig()
        val existing = rig.validPersistedGeneration()
        val existingKey = existing.keys.single()
        rig.stateStore.snapshot = existing
        rig.keyStore.entries[existingKey.internalAlias] = existingKey.metadata!!
        val replacement = testUuid(998)
        val ids = ArrayDeque(listOf(existingKey.keyId, replacement))

        val generated =
            rig.repository { ids.removeFirst() }
                .generate(rig.scope, rig.generateCommand(testUuid(260)))

        assertEquals(replacement, generated.handle.id)
        assertEquals(2, rig.stateStore.snapshot!!.keys.size)
        assertTrue(rig.stateStore.snapshot!!.keys.any { it.keyId == existingKey.keyId })
    }

    @Test
    fun persistentKeyIdCollisionFailsUnavailableBeforeWriteOrKeystoreEffect() {
        val rig = RepositoryTestRig()
        val existing = rig.validPersistedGeneration()
        val existingKey = existing.keys.single()
        rig.stateStore.snapshot = existing
        rig.keyStore.entries[existingKey.internalAlias] = existingKey.metadata!!
        val repository = rig.repository { existingKey.keyId }

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, rig.generateCommand(testUuid(261)))
        }

        assertEquals(0, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(1, rig.stateStore.snapshot!!.keys.size)
    }

    private fun preparedSnapshot(
        rig: RepositoryTestRig,
        command: BackendGenerate,
        keyId: java.util.UUID,
    ): DonorStateSnapshot {
        val key =
            DurableKeyRecord(
                keyId,
                rig.scope,
                command.logicalNameHash,
                DonorKeyAliasPolicy.aliasFor(keyId),
                KeyState.CREATING,
                null,
            )
        val mutation =
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.PREPARED,
                rig.scope,
                command.generationId,
                command.payloadHash,
                keyId,
                GenerateIntent(command.logicalNameHash, command.challenge, command.keySpec),
            )
        return DonorStateSnapshot(1uL, listOf(key), listOf(mutation))
    }
}
