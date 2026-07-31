package org.matrix.TEESimulator.rka.journal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.IrpcGeneratedKey
import org.matrix.TEESimulator.rka.broker.IrpcKeyBatch
import org.matrix.TEESimulator.rka.broker.RkpKeyCount

class RkpJournalTest {
    @Test
    fun persistsGeneratingBeforeRecordingOrderedResults() {
        val store = MemoryJournalStore()
        val journal = RkpJournal(store)
        val generating = journal.begin(count(2), RkpBatchId.fresh())

        assertEquals(
            RkpJournalState.RKP_KEY_GENERATING,
            RkpJournalCodec.decode(store.writes[0]).state,
        )
        val recorded =
            journal.record(
                generating,
                IrpcKeyBatch(
                    listOf(
                        IrpcGeneratedKey(byteArrayOf(1), byteArrayOf(81)),
                        IrpcGeneratedKey(byteArrayOf(2), byteArrayOf(82)),
                    )
                ),
            )

        assertEquals(listOf(0, 1), recorded.entries.map { it.order })
        assertEquals(
            RkpJournalState.RKP_KEY_RECORDED,
            RkpJournalCodec.decode(store.writes[1]).state,
        )
        assertTrue(store.writes.none { String(it).contains("81") || String(it).contains("82") })
    }

    @Test
    fun crashRecoveryIsDurableAndIdempotent() {
        val store = MemoryJournalStore()
        val journal = RkpJournal(store)
        journal.begin(count(1))

        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
        val writes = store.writes.size
        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
        assertEquals(writes, store.writes.size)
    }

    @Test
    fun postingCrashBecomesAmbiguousWithoutRetry() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = journal.record(journal.begin(count(1)), batch())
        val prepared = journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        journal.transition(prepared, RkpJournalState.CSR_POSTING)

        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
    }

    @Test
    fun appGeneratingCrashBecomesQuarantined() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = journal.record(journal.begin(count(1)), batch())
        val prepared = journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        val posting = journal.transition(prepared, RkpJournalState.CSR_POSTING)
        val certified = journal.transition(posting, RkpJournalState.RKP_CERTIFIED)
        journal.transition(certified, RkpJournalState.APP_KEY_GENERATING)

        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsTransitionSkip() {
        val journal = RkpJournal(MemoryJournalStore())
        journal.transition(journal.begin(count(1)), RkpJournalState.CSR_PREPARED)
    }

    @Test(expected = IllegalStateException::class)
    fun writeFailurePreventsNextState() {
        RkpJournal(MemoryJournalStore(fail = true)).begin(count(1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsDuplicateTransition() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = journal.record(journal.begin(count(1)), batch())
        journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        journal.transition(recorded, RkpJournalState.CSR_PREPARED)
    }

    private fun count(value: Int): RkpKeyCount =
        (RkpKeyCount.parse(value) as org.matrix.TEESimulator.rka.broker.BrokerOutcome.Success).value

    private fun batch(): IrpcKeyBatch =
        IrpcKeyBatch(listOf(IrpcGeneratedKey(byteArrayOf(1), byteArrayOf(81))))
}

private class MemoryJournalStore(private val fail: Boolean = false) : RkpJournalStore {
    val writes = mutableListOf<ByteArray>()

    override fun read(): ByteArray? = writes.lastOrNull()?.copyOf()

    override fun replace(value: ByteArray) {
        if (fail) throw IllegalStateException("storage")
        writes += value.copyOf()
    }
}
