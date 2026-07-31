package org.matrix.TEESimulator.rka.journal

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.DirectCallRunner
import org.matrix.TEESimulator.rka.broker.FakeIrpcEndpoint
import org.matrix.TEESimulator.rka.broker.FakeResolver
import org.matrix.TEESimulator.rka.broker.IrpcGeneratedKey
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.broker.testSpki

class RkpJournalTest {
    @Test
    fun persistsGeneratingBeforeRecordingOrderedResults() {
        val store = MemoryJournalStore()
        val journal = RkpJournal(store)
        val generating = journal.begin(count(2), identity(), RkpBatchId.fresh())

        assertEquals(
            RkpJournalState.RKP_KEY_GENERATING,
            RkpJournalCodec.decode(store.writes[0]).state,
        )
        val entries =
            journal.deriveEntries(
                generating,
                listOf(byteArrayOf(1) to testSpki(), byteArrayOf(2) to testSpki()),
            )
        val recorded = journal.record(generating, entries) {}

        assertEquals(listOf(0, 1), recorded.entries.map { it.order })
        assertEquals(
            RkpJournalState.RKP_KEY_RECORDED,
            RkpJournalCodec.decode(store.writes[1]).state,
        )
        assertFalse(store.writes.any { it.containsSubsequence(byteArrayOf(81, 82, 83, 84)) })
    }

    @Test
    fun batchRecordedBeforeCsr() {
        val order = mutableListOf<String>()
        val sync = RecordingSyncOps(order)
        val store = FileRkpJournalStore(Path.of("/journal/rkp"), sync)
        val calls = intArrayOf(0)
        val client =
            org.matrix.TEESimulator.rka.broker.IrpcClient(
                FakeResolver(
                    irpc =
                        FakeIrpcEndpoint(
                            onGenerate = {
                                calls[0] += 1
                                order += "hardware"
                            },
                            generated =
                                IrpcGeneratedKey(
                                    byteArrayOf(1),
                                    testSpki(),
                                    byteArrayOf(81, 82, 83, 84),
                                ),
                        )
                ),
                DirectCallRunner,
            )
        val generator = DurableIrpcKeyBatchGenerator(client, RkpJournal(store))

        val result =
            generator.batchRecordedBeforeCsr(
                count(1),
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            ) {
                order += "csr"
            }

        assertTrue(result is BrokerOutcome.Success)
        assertEquals(1, calls[0])
        assertFalse(sync.writes.any { it.containsSubsequence(byteArrayOf(81, 82, 83, 84)) })
        assertEquals(
            listOf(
                "temp",
                "write",
                "file-fsync",
                "rename",
                "parent-fsync",
                "hardware",
                "temp",
                "write",
                "file-fsync",
                "rename",
                "parent-fsync",
                "csr",
            ),
            order,
        )
    }

    @Test
    fun crashRecoveryIsDurableAndIdempotent() {
        val store = MemoryJournalStore()
        val journal = RkpJournal(store)
        journal.begin(count(1), identity())

        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
        val writes = store.writes.size
        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
        assertEquals(writes, store.writes.size)
    }

    @Test
    fun postingCrashBecomesAmbiguousWithoutRetry() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = recorded(journal)
        val prepared = journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        journal.transition(prepared, RkpJournalState.CSR_POSTING)

        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
    }

    @Test
    fun appGeneratingCrashBecomesQuarantined() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = recorded(journal)
        val prepared = journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        val posting = journal.transition(prepared, RkpJournalState.CSR_POSTING)
        val certified = journal.transition(posting, RkpJournalState.RKP_CERTIFIED)
        journal.transition(certified, RkpJournalState.APP_KEY_GENERATING)

        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsTransitionSkip() {
        val journal = RkpJournal(MemoryJournalStore())
        journal.transition(journal.begin(count(1), identity()), RkpJournalState.CSR_PREPARED)
    }

    @Test(expected = IllegalStateException::class)
    fun writeFailurePreventsNextState() {
        RkpJournal(MemoryJournalStore(fail = true)).begin(count(1), identity())
    }

    @Test
    fun writeFailurePreventsHardware() {
        val calls = intArrayOf(0)
        val generator =
            DurableIrpcKeyBatchGenerator(
                org.matrix.TEESimulator.rka.broker.IrpcClient(
                    FakeResolver(irpc = FakeIrpcEndpoint(onGenerate = { calls[0] += 1 })),
                    DirectCallRunner,
                ),
                RkpJournal(MemoryJournalStore(fail = true)),
            )

        assertThrows(IllegalStateException::class.java) {
            generator.generate(count(1), BrokerDeadline.at(5_000), BrokerCancellation.active())
        }
        assertEquals(0, calls[0])
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsDuplicateTransition() {
        val journal = RkpJournal(MemoryJournalStore())
        val recorded = recorded(journal)
        journal.transition(recorded, RkpJournalState.CSR_PREPARED)
        journal.transition(recorded, RkpJournalState.CSR_PREPARED)
    }

    @Test
    fun terminalDeleteClearsBrokerOwnerBeforeReturn() {
        val journal = RkpJournal(MemoryJournalStore())
        val generating = journal.begin(count(1), identity())
        var clears = 0
        var current =
            journal.record(
                generating,
                journal.deriveEntries(generating, listOf(byteArrayOf(1) to testSpki())),
            ) {
                clears += 1
            }
        current = journal.transition(current, RkpJournalState.CSR_PREPARED)
        current = journal.transition(current, RkpJournalState.CSR_POSTING)
        current = journal.transition(current, RkpJournalState.RKP_CERTIFIED)
        current = journal.transition(current, RkpJournalState.APP_KEY_GENERATING)
        current = journal.transition(current, RkpJournalState.APP_KEY_RECORDED)
        current = journal.transition(current, RkpJournalState.EXPOSED)
        current = journal.transition(current, RkpJournalState.TERMINAL)

        journal.transition(current, RkpJournalState.DELETE)

        assertEquals(1, clears)
    }

    private fun count(value: Int): RkpKeyCount =
        (RkpKeyCount.parse(value) as org.matrix.TEESimulator.rka.broker.BrokerOutcome.Success).value

    private fun recorded(journal: RkpJournal): RkpJournalRecord {
        val generating = journal.begin(count(1), identity())
        return journal.record(
            generating,
            journal.deriveEntries(generating, listOf(byteArrayOf(1) to testSpki())),
        ) {}
    }

    private fun identity(): RkpIrpcIdentity =
        RkpIrpcIdentity(
            org.matrix.TEESimulator.rka.broker.IrpcClient.IRPC_DESCRIPTOR,
            org.matrix.TEESimulator.rka.broker.IrpcClient.DEFAULT_TEE_SERVICE,
            "TEE",
            "fake-irpc",
            org.matrix.TEESimulator.rka.broker.IrpcClient.REQUIRED_VERSION,
        )
}

private class MemoryJournalStore(private val fail: Boolean = false) : RkpJournalStore {
    val writes = mutableListOf<ByteArray>()

    override fun read(): ByteArray? = writes.lastOrNull()?.copyOf()

    override fun replace(value: ByteArray) {
        if (fail) throw IllegalStateException("storage")
        writes += value.copyOf()
    }
}

private class RecordingSyncOps(private val order: MutableList<String>) : JournalSyncOps {
    private var current: ByteArray? = null
    private var temporary: ByteArray? = null
    val writes = mutableListOf<ByteArray>()

    override fun validateTarget(path: Path) {}

    override fun read(path: Path): ByteArray? = current?.copyOf()

    override fun createPrivateTemp(parent: Path): Path =
        parent.resolve("temp").also { order += "temp" }

    override fun write(path: Path, value: ByteArray) {
        order += "write"
        temporary = value.copyOf()
        writes += value.copyOf()
    }

    override fun fsyncFile(path: Path) {
        order += "file-fsync"
    }

    override fun atomicMove(source: Path, target: Path) {
        order += "rename"
        current = temporary
    }

    override fun fsyncDirectory(path: Path) {
        order += "parent-fsync"
    }

    override fun deleteIfExists(path: Path) {}
}

private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean =
    indices.any { start ->
        start + candidate.size <= size &&
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
    }
