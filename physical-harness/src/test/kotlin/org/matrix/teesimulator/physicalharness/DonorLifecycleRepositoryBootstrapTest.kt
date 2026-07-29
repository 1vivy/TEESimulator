package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import org.matrix.teesimulator.twophone.KeyState

class DonorLifecycleRepositoryBootstrapTest {
    @Test
    fun codecBackedSnapshotStoreAuthenticatesLoadAndAtomicallyEncodesSave() {
        val blobStore = MemoryDonorStateBlobStore()
        val codec = DonorStateCodec(TestHandleMac(testBytes(32, 120)))
        val store = CodecAuthenticatedDonorStateStore(blobStore, codec)
        assertNull(store.load())

        val expected = DonorStateSnapshot(0uL, emptyList(), emptyList())
        store.save(expected)

        assertEquals(0uL, store.load()!!.revision)
        assertContentEquals(blobStore.bytes, codec.encode(expected))
        blobStore.bytes = blobStore.bytes!!.mutated(20)
        assertFailsWith<DonorStateCorruptionException.AuthenticationFailed> { store.load() }
    }

    @Test
    fun missingStateWithNoOwnedAliasesBootstrapsWithoutWritingOrMutatingKeys() {
        val rig = RepositoryTestRig()

        rig.repository().recover()

        assertEquals(1, rig.stateStore.loadCount)
        assertEquals(0, rig.stateStore.saveAttempts)
        assertEquals(1, rig.keyStore.ownedAliasCalls)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun missingStateWithOwnedAliasLatchesGlobalQuarantineWithoutDeletion() {
        val rig = RepositoryTestRig()
        rig.keyStore.orphanAliases += DonorKeyAliasPolicy.aliasFor(testUuid(999))
        val repository = rig.repository()

        assertFailsWith<DonorLifecycleRepositoryException.GlobalQuarantine> { repository.recover() }
        rig.keyStore.orphanAliases.clear()
        assertFailsWith<DonorLifecycleRepositoryException.GlobalQuarantine> { repository.recover() }

        assertEquals(0, rig.stateStore.saveAttempts)
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun corruptOrUnstableStateLatchesBeforeAnyKeystoreAccessAndPreservesBytes() {
        listOf(
                DonorStateCorruptionException.AuthenticationFailed(),
                DonorStateQuarantineException.ImpossibleState(),
                DonorStateBlobStoreException.UnexpectedLength(),
            )
            .forEach { stateFailure ->
                val rig = RepositoryTestRig()
                rig.stateStore.loadFailure = stateFailure
                val repository = rig.repository()

                assertFailsWith<DonorLifecycleRepositoryException.GlobalQuarantine> {
                    repository.recover()
                }
                rig.stateStore.loadFailure = null
                assertFailsWith<DonorLifecycleRepositoryException.GlobalQuarantine> {
                    repository.recover()
                }
                assertEquals(0, rig.stateStore.saveAttempts)
                assertEquals(0, rig.keyStore.ownedAliasCalls)
                assertEquals(0, rig.keyStore.generateCalls)
                assertEquals(0, rig.keyStore.deleteCalls)
            }
    }

    @Test
    fun persistedPayloadHashMismatchGloballyQuarantinesBeforeInspection() {
        val rig = RepositoryTestRig()
        val valid = rig.validPersistedGeneration()
        val key = valid.keys.single()
        val generation = valid.mutations.single()
        rig.stateStore.snapshot =
            DonorStateSnapshot(
                valid.revision,
                valid.keys,
                listOf(
                    DurableMutationRecord(
                        generation.kind,
                        generation.phase,
                        generation.scope,
                        generation.mutationId,
                        testBytes(32, 127),
                        generation.keyId,
                        generation.generateIntent,
                    )
                ),
            )
        rig.keyStore.entries[key.internalAlias] = key.metadata!!

        assertFailsWith<DonorLifecycleRepositoryException.GlobalQuarantine> {
            rig.repository().recover()
        }

        assertEquals(0, rig.keyStore.ownedAliasCalls)
        assertEquals(0, rig.keyStore.inspectCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun ordinaryLoadIoIsUnavailableWithoutPermanentlyLatching() {
        val rig = RepositoryTestRig()
        val failure = TestRepositoryIoFailure()
        rig.stateStore.loadFailure = failure
        val repository = rig.repository()

        val unavailable =
            assertFailsWith<DonorLifecycleRepositoryException.Unavailable> { repository.recover() }
        assertSame(failure, unavailable.cause)
        rig.stateStore.loadFailure = null
        repository.recover()

        assertEquals(2, rig.stateStore.loadCount)
        assertEquals(0, rig.keyStore.generateCalls)
        assertEquals(0, rig.keyStore.deleteCalls)
    }

    @Test
    fun activeAndSupersededRecoveryQuarantinesMissingOrMismatchedMaterialWithoutRegeneration() {
        listOf(KeyState.ACTIVE, KeyState.SUPERSEDED).forEach { state ->
            listOf("absent", "rejected", "mismatch").forEach { condition ->
                val rig = RepositoryTestRig()
                val snapshot = rig.validPersistedGeneration(state = state)
                val key = snapshot.keys.single()
                rig.stateStore.snapshot = snapshot
                when (condition) {
                    "rejected" ->
                        rig.keyStore.inspectionOverrides[key.internalAlias] =
                            DurableKeyInspection.Rejected
                    "mismatch" ->
                        rig.keyStore.entries[key.internalAlias] =
                            repositoryMetadata(state, testBytes(32, 126), 127)
                }

                rig.repository().recover()

                assertEquals(KeyState.QUARANTINED, rig.stateStore.snapshot!!.keys.single().state)
                assertEquals(
                    DurableMutationPhase.QUARANTINED,
                    rig.stateStore.snapshot!!.mutations.single().phase,
                )
                assertEquals(0, rig.keyStore.generateCalls)
                assertEquals(0, rig.keyStore.deleteCalls)
            }
        }
    }

    private class MemoryDonorStateBlobStore : DonorStateBlobStore {
        var bytes: ByteArray? = null

        override fun read(): ByteArray? = bytes?.copyOf()

        override fun write(blob: ByteArray) {
            bytes = blob.copyOf()
        }
    }
}
