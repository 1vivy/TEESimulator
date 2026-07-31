package org.matrix.TEESimulator.rka.broker

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BrokerBatchId
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.RequestId
import org.matrix.TEESimulator.rka.journal.RkpBatchId
import org.matrix.TEESimulator.rka.journal.RkpIrpcIdentity
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalState
import org.matrix.TEESimulator.rka.journal.RkpJournalStore

class FreshBatchQuarantineLifecycleTest {
    @Test
    fun twoPostAmbiguousBatchesCompleteIndependentlyAndExactReplaysHaveNoEffects() {
        val store = LifecycleStore()
        val journal = RkpJournal(store)
        val receipts = KeyedMemoryReceipts()
        var effects = 0
        var blobClears = 0
        val controller = controller(journal, receipts) { effects++ }
        val batchA = ByteArray(16) { 1 }
        val handleA = preparePostAmbiguous(journal, batchA) { blobClears++ }

        assertEquals(
            QuarantineResult.QUARANTINED,
            controller.quarantine(request(101, batchA, handleA)),
        )
        assertNull(store.read())
        assertEquals(3, effects)
        assertEquals(1, blobClears)
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller.quarantine(request(101, batchA, handleA)),
        )
        assertEquals(3, effects)

        val batchB = ByteArray(16) { 2 }
        val handleB = preparePostAmbiguous(journal, batchB) { blobClears++ }
        assertFalse(handleA.contentEquals(handleB))
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller.quarantine(request(101, batchA, handleA)),
        )
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller.quarantine(request(202, batchB, handleB)),
        )

        assertNull(store.read())
        assertEquals(6, effects)
        assertEquals(2, blobClears)
        assertEquals(2, receipts.count)
        assertFalse(controller.activationAllowed(RequestId(101)))
        assertFalse(controller.activationAllowed(RequestId(202)))
        assertEquals(
            QuarantineResult.HANDLE_MISMATCH,
            controller.quarantine(request(303, batchA, handleA)),
        )
        assertEquals(6, effects)
    }

    @Test
    fun tombstoneBeforeJournalClearResumesClearWithoutRepeatingEffects() {
        val store = LifecycleStore(failFirstClear = true)
        val journal = RkpJournal(store)
        val receipts = KeyedMemoryReceipts()
        val batch = ByteArray(16) { 7 }
        val handle = preparePostAmbiguous(journal, batch) {}
        var effects = 0
        val first = controller(journal, receipts) { effects++ }

        assertThrows(IllegalStateException::class.java) {
            first.quarantine(request(707, batch, handle))
        }
        assertEquals(3, effects)
        assertEquals(RkpJournalState.DELETE, journal.recover()?.state)
        assertEquals(1, receipts.count)

        val restarted = controller(journal, receipts) { effects++ }
        assertEquals(
            QuarantineResult.QUARANTINED,
            restarted.quarantine(request(707, batch, handle)),
        )
        assertEquals(3, effects)
        assertNull(store.read())
        assertNotNull(journal.begin(count(), identity(), RkpBatchId.from(ByteArray(16) { 8 })))
    }

    @Test
    fun missingCompletionTombstoneKeepsJournalAndBlocksFreshBegin() {
        val store = LifecycleStore()
        val journal = RkpJournal(store)
        val batch = ByteArray(16) { 9 }
        val handle = preparePostAmbiguous(journal, batch) {}
        val rejectingReceipts =
            object : QuarantineReceiptStore {
                override fun read(key: ByteArray): ByteArray? = null

                override fun create(key: ByteArray, receipt: ByteArray): Boolean = false
            }
        val controller = controller(journal, rejectingReceipts) {}

        assertEquals(
            QuarantineResult.CLEANUP_INCOMPLETE,
            controller.quarantine(request(909, batch, handle)),
        )
        assertEquals(RkpJournalState.QUARANTINED, journal.recover()?.state)
        assertThrows(IllegalStateException::class.java) {
            journal.begin(count(), identity(), RkpBatchId.from(ByteArray(16) { 10 }))
        }
    }

    private fun controller(
        journal: RkpJournal,
        receipts: QuarantineReceiptStore,
        effect: () -> Unit,
    ) =
        QuarantineController(
            exactQuarantine = journal::quarantineHandles,
            cancel = effect,
            discard = { effect() },
            wipe = { effect() },
            receipts = receipts,
            expectedBatch = { journal.recover()?.batchId?.copyBytes() },
            complete = journal::completeQuarantine,
            requireActiveBatch = true,
        )

    private fun preparePostAmbiguous(
        journal: RkpJournal,
        batch: ByteArray,
        clear: () -> Unit,
    ): ByteArray {
        val generating = journal.begin(count(), identity(), RkpBatchId.from(batch))
        val entries = journal.deriveEntries(generating, listOf(byteArrayOf(batch[0]) to testSpki()))
        var current =
            journal.record(generating, entries, resolveBlob = { true }, clearBlobs = clear)
        current = journal.transition(current, RkpJournalState.CSR_PREPARED)
        current = journal.transition(current, RkpJournalState.CSR_POSTING)
        journal.transition(current, RkpJournalState.POST_AMBIGUOUS)
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
        return entries.single().handle.copyBytes()
    }

    private fun request(
        requestId: Long,
        batch: ByteArray,
        handle: ByteArray,
    ): AuthenticatedQuarantineRequest {
        val batchId = BrokerBatchId.of(batch)
        val actionIds = actionIds(requestId, batch, handle).map(Hash32::of)
        return try {
            AuthenticatedQuarantineRequest.fromTrustedBridge(
                RequestId(requestId),
                listOf(handle),
                batchId,
                actionIds,
            )
        } finally {
            batchId.close()
            actionIds.forEach(Hash32::close)
        }
    }

    private fun actionIds(requestId: Long, batch: ByteArray, handle: ByteArray): List<ByteArray> {
        fun derive(tag: Int, value: ByteArray?): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("TEESimulator-RS quarantine action v1\u0000".toByteArray())
            digest.update(
                ByteBuffer.allocate(Long.SIZE_BYTES)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putLong(requestId)
                    .array()
            )
            digest.update(batch)
            digest.update(tag.toByte())
            value?.let(digest::update)
            return digest.digest()
        }
        return listOf(derive(0, null), derive(1, handle), derive(2, handle))
    }

    private fun count(): RkpKeyCount = (RkpKeyCount.parse(1) as BrokerOutcome.Success).value

    private fun identity() =
        RkpIrpcIdentity(
            IrpcClient.IRPC_DESCRIPTOR,
            IrpcClient.DEFAULT_TEE_SERVICE,
            "TEE",
            "fresh-batch-test",
            IrpcClient.REQUIRED_VERSION,
        )
}

private class KeyedMemoryReceipts : QuarantineReceiptStore {
    private val values = linkedMapOf<String, ByteArray>()
    val count: Int
        get() = values.size

    override fun read(key: ByteArray): ByteArray? = values[key.hex()]?.copyOf()

    override fun create(key: ByteArray, receipt: ByteArray): Boolean {
        val name = key.hex()
        if (name in values) return false
        values[name] = receipt.copyOf()
        return true
    }
}

private class LifecycleStore(private val failFirstClear: Boolean = false) : RkpJournalStore {
    private var value: ByteArray? = null
    private var clearFailed = false

    override fun read(): ByteArray? = value?.copyOf()

    override fun replace(value: ByteArray) {
        this.value = value.copyOf()
    }

    override fun clear() {
        if (failFirstClear && !clearFailed) {
            clearFailed = true
            throw IllegalStateException("injected clear crash")
        }
        value = null
    }
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
