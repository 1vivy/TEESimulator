package org.matrix.TEESimulator.rka.candidate

import java.nio.file.Files
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class CandidateStateIsolationTest {
    @Test
    fun candidateStoresAndSyntheticLeaseRecordsAreDisjointAcrossCandidates() {
        // Given
        val baseRoot = Files.createTempDirectory("candidate-state-isolation-")
        val firstIdentity = IdentityHash.of(ByteArray(32) { 1 })
        val secondIdentity = IdentityHash.of(ByteArray(32) { 2 })
        val identities = listOf(firstIdentity, secondIdentity)
        val stores = identities.associateWith { FileRemoteCandidateStore(baseRoot, it) }
        val leaseStores = identities.associateWith { FileSyntheticLeaseStore(baseRoot, it) }
        val id = CandidateKeyId(10_123, 10_123L, "shared-alias")
        stores.getValue(firstIdentity).replace(record(id, firstIdentity))

        // When
        val firstRecord = stores.getValue(firstIdentity).find(id)
        val secondRecord = stores.getValue(secondIdentity).find(id)
        val firstLeaseStore = leaseStores.getValue(firstIdentity)
        val secondLeaseStore = leaseStores.getValue(secondIdentity)

        // Then
        assertNotNull(firstRecord)
        assertNull(secondRecord)
        assertNotEquals(firstLeaseStore.leaseStatePath, secondLeaseStore.leaseStatePath)
        assertNotEquals(
            firstLeaseStore.pairedActivationRecordPath,
            secondLeaseStore.pairedActivationRecordPath,
        )
    }

    private fun record(id: CandidateKeyId, identity: IdentityHash) =
        CandidateKeyRecord(
            id,
            identity,
            1,
            1,
            RemoteKeyHandle.of(ByteArray(16) { 3 }),
            listOf(byteArrayOf(1), byteArrayOf(2)),
            CandidateCharacteristics.foreground(),
            CandidateKeyState.CONSUMED,
        )

}
