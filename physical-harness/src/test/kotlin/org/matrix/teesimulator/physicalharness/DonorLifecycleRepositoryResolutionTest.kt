package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DonorLifecycleRepositoryResolutionTest {
    @Test
    fun supersededResolvesWhileCreatingPendingDeletedAndQuarantinedDoNot() {
        val supersededRig = RepositoryTestRig()
        val supersededRepository = supersededRig.repository()
        val logicalName = testBytes(32, 91)
        val first =
            supersededRepository.generate(
                supersededRig.scope,
                supersededRig.generateCommand(testUuid(410), logicalName, testBytes(32, 92)),
            )
        supersededRepository.generate(
            supersededRig.scope,
            supersededRig.generateCommand(testUuid(411), logicalName, testBytes(32, 93)),
        )
        assertEquals(
            first.handle.id,
            supersededRepository.resolveForBegin(supersededRig.scope, first.handle).keyId,
        )

        val creatingRig = RepositoryTestRig()
        val creatingRepository = creatingRig.repository()
        creatingRig.keyStore.generateFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            creatingRepository.generate(creatingRig.scope, creatingRig.generateCommand())
        }
        val creatingKey = creatingRig.stateStore.snapshot!!.keys.single()
        val creatingHandle =
            creatingRig.authenticator.createKeyHandle(creatingRig.scope, creatingKey.keyId)
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            creatingRepository.resolveForBegin(creatingRig.scope, creatingHandle)
        }

        val deletionRig = RepositoryTestRig()
        val deletionRepository = deletionRig.repository()
        val generated =
            deletionRepository.generate(deletionRig.scope, deletionRig.generateCommand())
        deletionRig.keyStore.deleteFailure = TestBackendUncertainty()
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            deletionRepository.delete(
                deletionRig.scope,
                deletionRig.deleteCommand(generated.handle.id),
            )
        }
        assertFailsWith<DonorLifecycleRepositoryException.Unavailable> {
            deletionRepository.resolveForBegin(deletionRig.scope, generated.handle)
        }
        deletionRig.keyStore.deleteFailure = null
        deletionRig.keyStore.entries.clear()
        deletionRepository.recover()
        assertFailsWith<DonorLifecycleRepositoryException.InvalidState> {
            deletionRepository.resolveForBegin(deletionRig.scope, generated.handle)
        }

        val quarantinedRig = RepositoryTestRig()
        val quarantinedRepository = quarantinedRig.repository()
        val quarantinedGenerated =
            quarantinedRepository.generate(quarantinedRig.scope, quarantinedRig.generateCommand())
        val alias = quarantinedRig.stateStore.snapshot!!.keys.single().internalAlias
        quarantinedRig.keyStore.entries[alias] =
            repositoryMetadata(
                org.matrix.teesimulator.twophone.KeyState.ACTIVE,
                testBytes(32, 94),
                95,
            )
        assertFailsWith<DonorLifecycleRepositoryException.InvalidState> {
            quarantinedRepository.delete(
                quarantinedRig.scope,
                quarantinedRig.deleteCommand(quarantinedGenerated.handle.id),
            )
        }
        assertFailsWith<DonorLifecycleRepositoryException.InvalidState> {
            quarantinedRepository.resolveForBegin(quarantinedRig.scope, quarantinedGenerated.handle)
        }
    }
}
