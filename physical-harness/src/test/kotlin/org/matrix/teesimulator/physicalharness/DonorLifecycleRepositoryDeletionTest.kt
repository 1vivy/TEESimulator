package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireKeyHandle

class DonorLifecycleRepositoryDeletionTest {
    @Test
    fun wrongHandleOrScopeFailsBeforeAnyAliasAccess() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        rig.keyStore.resetCalls()
        val wrongHandle = WireKeyHandle(generated.handle.id, generated.handle.binding.mutated(0))
        val deletionId = testUuid(320)
        val wrongHandleCommand =
            BackendDelete(
                deletionId,
                NormalizedWireCodec.payloadHash(DeleteRequestPayload(deletionId, wrongHandle)),
                wrongHandle,
                rig.scope.caller,
            )

        assertFailsWith<DonorLifecycleRepositoryException.InvalidHandle> {
            repository.delete(rig.scope, wrongHandleCommand)
        }
        val valid = rig.deleteCommand(generated.handle.id, testUuid(321))
        assertFailsWith<DonorLifecycleRepositoryException.InvalidHandle> {
            repository.delete(testScope(202), valid)
        }

        assertEquals(0, rig.keyStore.ownedAliasCalls)
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun pendingWriteFailurePerformsNoDeletion() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id)
        rig.stateStore.failBeforeSaveAttempts += rig.stateStore.saveAttempts + 1

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.delete(rig.scope, command)
        }

        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(KeyState.ACTIVE, rig.stateStore.snapshot!!.keys.single().state)
    }

    @Test
    fun pendingExactRecoveryRetriesOneGuardedDeleteAndCommits() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id)
        val uncertainty = TestBackendUncertainty()
        rig.keyStore.deleteFailure = uncertainty

        val unavailable =
            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
                repository.delete(rig.scope, command)
            }
        assertSame(uncertainty, unavailable.cause)
        assertEquals(KeyState.DELETE_PENDING, rig.stateStore.snapshot!!.keys.single().state)
        rig.keyStore.deleteFailure = null

        rig.repository().recover()

        assertEquals(2, rig.keyStore.deleteCalls)
        assertEquals(KeyState.DELETED, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(DurableMutationPhase.COMMITTED, deletion(rig).phase)
    }

    @Test
    fun differentRequestReconcilesLoadedPendingDeletionBeforePreparingGeneration() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand(testUuid(340)))
        rig.keyStore.deleteFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.delete(rig.scope, rig.deleteCommand(generated.handle.id, testUuid(341)))
        }
        val savesAfterPrepare = rig.stateStore.saveAttempts
        val nextGeneration =
            rig.generateCommand(testUuid(342), testBytes(32, 88), testBytes(32, 89))

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.generate(rig.scope, nextGeneration)
        }
        assertEquals(savesAfterPrepare, rig.stateStore.saveAttempts)
        assertEquals(
            1,
            rig.stateStore.snapshot!!.mutations.count { it.phase == DurableMutationPhase.PREPARED },
        )

        rig.keyStore.deleteFailure = null
        repository.generate(rig.scope, nextGeneration)
        assertEquals(
            KeyState.DELETED,
            rig.stateStore.snapshot!!.keys.first { it.keyId == generated.handle.id }.state,
        )
        assertEquals(
            0,
            rig.stateStore.snapshot!!.mutations.count { it.phase == DurableMutationPhase.PREPARED },
        )
    }

    @Test
    fun pendingAbsentRecoveryCommitsWithoutAnotherDeleteAttempt() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id)
        rig.keyStore.deleteFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.delete(rig.scope, command)
        }
        rig.keyStore.deleteFailure = null
        rig.keyStore.entries.clear()
        rig.keyStore.resetCalls()

        rig.repository().recover()

        assertEquals(2, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(KeyState.DELETED, rig.stateStore.snapshot!!.keys.single().state)
    }

    @Test
    fun pendingMismatchQuarantinesWithoutDeletingReboundMaterial() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id)
        rig.keyStore.deleteFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.delete(rig.scope, command)
        }
        rig.keyStore.deleteFailure = null
        val alias = rig.stateStore.snapshot!!.keys.single().internalAlias
        rig.keyStore.entries[alias] = repositoryMetadata(KeyState.ACTIVE, testBytes(32, 123), 124)
        rig.keyStore.resetCalls()

        rig.repository().recover()

        assertEquals(KeyState.QUARANTINED, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(DurableMutationPhase.QUARANTINED, deletion(rig).phase)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(1, rig.keyStore.entries.size)
    }

    @Test
    fun postDeleteCommitFailureRecoversFromObservedAbsence() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id)
        rig.stateStore.failBeforeSaveAttempts += rig.stateStore.saveAttempts + 2

        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            repository.delete(rig.scope, command)
        }
        assertEquals(1, rig.keyStore.deleteCalls)
        assertEquals(KeyState.DELETE_PENDING, rig.stateStore.snapshot!!.keys.single().state)

        rig.repository().recover()

        assertEquals(1, rig.keyStore.deleteCalls)
        assertEquals(KeyState.DELETED, rig.stateStore.snapshot!!.keys.single().state)
    }

    @Test
    fun afterSaveAmbiguityForPreparedAndCommittedDeletionConvergesWithoutDuplicateDelete() {
        listOf(3, 4).forEach { ambiguousAttempt ->
            val rig = RepositoryTestRig()
            val repository = rig.repository()
            val generated = repository.generate(rig.scope, rig.generateCommand())
            val command = rig.deleteCommand(generated.handle.id, testUuid(350 + ambiguousAttempt))
            rig.stateStore.failAfterSaveAttempts += ambiguousAttempt

            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
                repository.delete(rig.scope, command)
            }
            repository.delete(rig.scope, command)

            assertEquals(1, rig.keyStore.deleteCalls)
            assertEquals(KeyState.DELETED, rig.stateStore.snapshot!!.keys.single().state)
        }
    }

    @Test
    fun committedReplayIsNoOpWhileNewDeletionIdAddsCommittedJournal() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val first = rig.deleteCommand(generated.handle.id, testUuid(330))
        repository.delete(rig.scope, first)
        rig.keyStore.resetCalls()
        val saves = rig.stateStore.saveAttempts

        repository.delete(rig.scope, first)
        assertEquals(saves, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.deleteCalls)

        repository.delete(rig.scope, rig.deleteCommand(generated.handle.id, testUuid(331)))
        assertEquals(saves + 1, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(
            2,
            rig.stateStore.snapshot!!.mutations.count {
                it.kind == DurableMutationKind.DELETE && it.phase == DurableMutationPhase.COMMITTED
            },
        )
    }

    @Test
    fun conflictingDeletionReplayDoesNotInspectOrDelete() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val command = rig.deleteCommand(generated.handle.id, testUuid(332))
        repository.delete(rig.scope, command)
        rig.keyStore.resetCalls()
        val conflict =
            rig.deleteCommand(
                generated.handle.id,
                command.deletionId,
                payloadHash = testBytes(32, 125),
            )

        assertFailsWith<DonorLifecycleRepositoryException.ReplayConflict> {
            repository.delete(rig.scope, conflict)
        }
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun reboundAliasBeforeIntentIsQuarantinedAndNeverDeleted() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        val alias = rig.stateStore.snapshot!!.keys.single().internalAlias
        rig.keyStore.entries[alias] = repositoryMetadata(KeyState.ACTIVE, testBytes(32, 126), 127)
        rig.keyStore.resetCalls()

        assertFailsWith<DonorLifecycleRepositoryException.InvalidState> {
            repository.delete(rig.scope, rig.deleteCommand(generated.handle.id))
        }

        assertEquals(KeyState.QUARANTINED, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(DurableMutationPhase.QUARANTINED, deletion(rig).phase)
        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(1, rig.keyStore.entries.size)
    }

    @Test
    fun reboundBetweenInspectionAndGuardedDeleteQuarantinesWithoutRemoval() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        rig.keyStore.forcedDeleteOutcome = DurableDeleteOutcome.MISMATCH

        assertFailsWith<DonorLifecycleRepositoryException.InvalidState> {
            repository.delete(rig.scope, rig.deleteCommand(generated.handle.id))
        }

        assertEquals(1, rig.keyStore.deleteCalls)
        assertEquals(1, rig.keyStore.entries.size)
        assertEquals(KeyState.QUARANTINED, rig.stateStore.snapshot!!.keys.single().state)
        assertEquals(DurableMutationPhase.QUARANTINED, deletion(rig).phase)
    }

    @Test
    fun deletedExactAliasIsGuardedlyRedeletedDuringRecovery() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        repository.delete(rig.scope, rig.deleteCommand(generated.handle.id))
        val persistedKey = rig.stateStore.snapshot!!.keys.single()
        rig.keyStore.entries[persistedKey.internalAlias] = persistedKey.metadata!!
        rig.keyStore.resetCalls()
        val saves = rig.stateStore.saveAttempts

        rig.repository().recover()

        assertEquals(1, rig.keyStore.deleteCalls)
        assertEquals(0, rig.keyStore.entries.size)
        assertEquals(saves, rig.stateStore.saveAttempts)
        assertEquals(KeyState.DELETED, rig.stateStore.snapshot!!.keys.single().state)
    }

    @Test
    fun maximumRevisionRejectsDeletedAliasCleanupBeforeSideEffect() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val generated = repository.generate(rig.scope, rig.generateCommand())
        repository.delete(rig.scope, rig.deleteCommand(generated.handle.id))
        val deleted = rig.stateStore.snapshot!!
        rig.stateStore.snapshot =
            DonorStateSnapshot(ULong.MAX_VALUE, deleted.keys, deleted.mutations)
        val key = deleted.keys.single()
        rig.keyStore.entries[key.internalAlias] = key.metadata!!
        rig.keyStore.resetCalls()

        assertFailsWith<DonorLifecycleRepositoryException.RevisionExhausted> {
            rig.repository().recover()
        }

        assertEquals(0, rig.keyStore.deleteCalls)
        assertEquals(1, rig.keyStore.entries.size)
    }

    private fun deletion(rig: RepositoryTestRig) =
        rig.stateStore.snapshot!!.mutations.single { it.kind == DurableMutationKind.DELETE }
}
