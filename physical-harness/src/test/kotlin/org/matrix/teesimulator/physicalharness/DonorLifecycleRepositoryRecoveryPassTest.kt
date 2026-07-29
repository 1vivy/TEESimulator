package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.matrix.teesimulator.twophone.KeyState

class DonorLifecycleRepositoryRecoveryPassTest {
    @Test
    fun failedInspectionRemainsStickyAcrossReadsUntilRecoverySucceeds() {
        val rig = RepositoryTestRig()
        val snapshot = rig.validPersistedGeneration()
        val key = snapshot.keys.single()
        val handle = rig.authenticator.createKeyHandle(rig.scope, key.keyId)
        rig.stateStore.snapshot = snapshot
        rig.keyStore.entries[key.internalAlias] = key.metadata!!
        rig.keyStore.inspectionFailures[key.internalAlias] = TestBackendUncertainty()
        val repository = rig.repository()

        repeat(2) {
            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
                repository.metadata(rig.scope, handle)
            }
        }
        assertEquals(2, rig.keyStore.inspectCalls)
        assertEquals(0, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)

        rig.keyStore.inspectionFailures.clear()
        assertEquals(KeyState.ACTIVE, repository.metadata(rig.scope, handle).state)
        assertEquals(3, rig.keyStore.inspectCalls)
    }

    @Test
    fun oneRecoveryQuarantinesEveryMissingLiveKey() {
        val rig = RepositoryTestRig()
        val first =
            rig.validPersistedGeneration(
                keyId = testUuid(710),
                generationId = testUuid(711),
                logicalNameHash = testBytes(32, 10),
                challenge = testBytes(32, 11),
            )
        val second =
            rig.validPersistedGeneration(
                keyId = testUuid(712),
                generationId = testUuid(713),
                logicalNameHash = testBytes(32, 12),
                challenge = testBytes(32, 13),
            )
        rig.stateStore.snapshot =
            DonorStateSnapshot(2uL, first.keys + second.keys, first.mutations + second.mutations)

        rig.repository().recover()

        assertEquals(2, rig.stateStore.snapshot!!.keys.count { it.state == KeyState.QUARANTINED })
        assertEquals(
            2,
            rig.stateStore.snapshot!!.mutations.count {
                it.phase == DurableMutationPhase.QUARANTINED
            },
        )
    }

    @Test
    fun oneRecoveryGuardDeletesEveryReappearedDeletedKey() {
        val rig = RepositoryTestRig()
        val repository = rig.repository()
        val first = repository.generate(rig.scope, rig.generateCommand(testUuid(720)))
        val second =
            repository.generate(
                rig.scope,
                rig.generateCommand(testUuid(721), testBytes(32, 22), testBytes(32, 23)),
            )
        repository.delete(rig.scope, rig.deleteCommand(first.handle.id, testUuid(722)))
        repository.delete(rig.scope, rig.deleteCommand(second.handle.id, testUuid(723)))
        rig.stateStore.snapshot!!.keys.forEach { key ->
            rig.keyStore.entries[key.internalAlias] = key.metadata!!
        }
        rig.keyStore.resetCalls()

        rig.repository().recover()

        assertEquals(2, rig.keyStore.deleteCalls)
        assertEquals(0, rig.keyStore.entries.size)
    }
}
