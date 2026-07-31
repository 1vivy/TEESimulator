package org.matrix.TEESimulator.rka.broker

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.journal.RkpCertification
import org.matrix.TEESimulator.rka.journal.RkpCertifiedKey
import org.matrix.TEESimulator.rka.journal.RkpIrpcIdentity
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalStore

class IrpcKeyBatchTest {
    @Test
    fun preservesHardwareOrderAndRedactsBlobs() {
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(
                    IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(91)),
                    IrpcGeneratedKey(byteArrayOf(2), testSpki(), byteArrayOf(92)),
                ),
            )

        assertArrayEquals(byteArrayOf(1), batch.publicKeys()[0])
        assertArrayEquals(byteArrayOf(2), batch.publicKeys()[1])
        assertEquals("IrpcKeyBatch(count=2)", batch.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsDuplicatePublicKeys() {
        IrpcKeyBatch(
            testIrpcIdentity(),
            listOf(
                IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(2)),
                IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(3)),
            ),
        )
    }

    @Test
    fun retainedBlobIsWipedAndRemovedOnClear() {
        val wiped = mutableListOf<ByteArray>()
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(81, 82, 83, 84))),
                { wiped += it },
            )
        val journal = RkpJournal(TestJournalStore())
        val count = (RkpKeyCount.parse(1) as BrokerOutcome.Success).value
        val intent = journal.begin(count, RkpIrpcIdentity.from(testIrpcIdentity()))
        val entries = journal.deriveEntries(intent, batch.publicKeys().zip(batch.spkiPublicKeys()))
        batch.recordInJournal(journal, intent, entries)
        batch.wipe()

        assertTrue(wiped.single().all { it == 0.toByte() })
        assertFalse(batch.toString().toByteArray().containsSubsequence(byteArrayOf(81, 82, 83, 84)))
    }

    @Test
    fun authenticatedCleanupDetachesThenWipesTheExactOwnedBlobOnce() {
        val wiped = mutableListOf<ByteArray>()
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(IrpcGeneratedKey(byteArrayOf(3), testSpki(), byteArrayOf(71, 72, 73))),
                { wiped += it.copyOf() },
            )
        val journal = RkpJournal(TestJournalStore())
        val count = (RkpKeyCount.parse(1) as BrokerOutcome.Success).value
        val intent = journal.begin(count, RkpIrpcIdentity.from(testIrpcIdentity()))
        val entries = journal.deriveEntries(intent, batch.publicKeys().zip(batch.spkiPublicKeys()))
        batch.recordInJournal(journal, intent, entries)
        val handle = entries.single().handle.copyBytes()

        assertFalse(journal.retainedBlobDiscarded(handle))
        journal.discardRetainedBlob(handle)
        assertTrue(journal.retainedBlobDiscarded(handle))
        assertFalse(journal.retainedBlobWiped(handle))
        journal.discardRetainedBlob(handle)
        journal.wipeRetainedBlob(handle)
        journal.wipeRetainedBlob(handle)

        assertTrue(journal.retainedBlobWiped(handle))
        assertEquals(1, wiped.size)
        assertTrue(wiped.single().all { it == 0.toByte() })
    }

    @Test
    fun exactOrderedHandlesResolveRetainedBlobsBeforeQuarantine() {
        val (journal, handles) = recordedTwoKeyBatch()

        assertTrue(journal.quarantineHandles(handles))
    }

    @Test
    fun mutatedHandleRejectsAndQuarantinesRetainedBlobs() {
        val (journal, handles) = recordedTwoKeyBatch()
        handles[1][0] = (handles[1][0].toInt() xor 1).toByte()

        assertFalse(journal.quarantineHandles(handles))
        assertFalse(journal.quarantineHandles(handles))
    }

    @Test
    fun certificationResolvesEveryRetainedBlobAndCommitsCertifiedAtomically() {
        val (journal, record) = certificationFixture()
        val certification = certification(record, 77)

        assertTrue(journal.certifyCurrent(certification))
        assertEquals(
            org.matrix.TEESimulator.rka.journal.RkpJournalState.RKP_CERTIFIED,
            journal.recover()?.state,
        )
    }

    @Test
    fun certificationMutationOrReplayQuarantinesWithoutCertifiedSuccess() {
        val (journal, record) = certificationFixture()
        val certification = certification(record, 78)
        val mutated =
            RkpCertification(
                certification.requestId,
                certification.batchId,
                certification.keys.mapIndexed { index, key ->
                    RkpCertifiedKey(
                        key.order,
                        key.handle,
                        key.copyPublicHash(),
                        key.copySpkiHash(),
                        if (index == 1) ByteArray(32) { 99 } else key.copyChainHash(),
                        key.certificateCount,
                    )
                },
                certification.profileEpoch,
                certification.copyActivationBindingHash(),
            )

        assertFalse(journal.certifyCurrent(mutated))
        assertFalse(journal.certifyCurrent(certification))
        assertEquals(
            org.matrix.TEESimulator.rka.journal.RkpJournalState.QUARANTINED,
            journal.recover()?.state,
        )
    }

    private fun recordedTwoKeyBatch(): Pair<RkpJournal, MutableList<ByteArray>> {
        val (journal, record) = certificationFixture()
        return journal to record.entries.map { it.handle.copyBytes() }.toMutableList()
    }

    private fun certificationFixture():
        Pair<RkpJournal, org.matrix.TEESimulator.rka.journal.RkpJournalRecord> {
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(
                    IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(81)),
                    IrpcGeneratedKey(byteArrayOf(2), testSpki(), byteArrayOf(82)),
                ),
            )
        val journal = RkpJournal(TestJournalStore())
        val count = (RkpKeyCount.parse(2) as BrokerOutcome.Success).value
        val intent = journal.begin(count, RkpIrpcIdentity.from(testIrpcIdentity()))
        val entries = journal.deriveEntries(intent, batch.publicKeys().zip(batch.spkiPublicKeys()))
        batch.recordInJournal(journal, intent, entries)
        val recorded = requireNotNull(journal.recover())
        val prepared =
            journal.transition(
                recorded,
                org.matrix.TEESimulator.rka.journal.RkpJournalState.CSR_PREPARED,
            )
        return journal to prepared
    }

    private fun certification(
        record: org.matrix.TEESimulator.rka.journal.RkpJournalRecord,
        requestId: Long,
    ): RkpCertification =
        RkpCertification(
            requestId,
            record.batchId,
            record.entries.map { entry ->
                RkpCertifiedKey(
                    entry.order,
                    entry.handle,
                    entry.copyPublicHash(),
                    entry.copySpkiHash(),
                    ByteArray(32) { (entry.order + 20).toByte() },
                    2,
                )
            },
            7,
            task14Binding(record, requestId),
        )

    private fun task14Binding(
        record: org.matrix.TEESimulator.rka.journal.RkpJournalRecord,
        requestId: Long,
    ): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        record.entries.forEach { entry ->
            val lease = MessageDigest.getInstance("SHA-256")
            lease.update("TEESimulator-RS activation v1\u0000".toByteArray())
            lease.update("lease".toByteArray())
            lease.update(
                ByteBuffer.allocate(Long.SIZE_BYTES)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putLong(requestId)
                    .array()
            )
            lease.update(entry.copySpkiHash())
            digest.update(lease.digest().copyOf(16))
            digest.update(record.batchId.copyBytes())
            digest.update(entry.order.toByte())
            digest.update(entry.copyPublicHash())
            digest.update(entry.copySpkiHash())
            digest.update(ByteArray(32) { (entry.order + 20).toByte() })
            digest.update(2.toByte())
            digest.update(
                ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(7L).array()
            )
        }
        return digest.digest()
    }
}

private class TestJournalStore : RkpJournalStore {
    private var bytes: ByteArray? = null

    override fun read(): ByteArray? = bytes?.copyOf()

    override fun replace(value: ByteArray) {
        bytes = value.copyOf()
    }
}

private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean =
    indices.any { start ->
        start + candidate.size <= size &&
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
    }
