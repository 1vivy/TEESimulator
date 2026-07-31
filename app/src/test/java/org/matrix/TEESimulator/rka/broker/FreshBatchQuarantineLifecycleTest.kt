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
import org.matrix.TEESimulator.rka.bridge.DonorProvisioningRuntime
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.RequestId
import org.matrix.TEESimulator.rka.journal.RkpBatchId
import org.matrix.TEESimulator.rka.journal.RkpIrpcIdentity
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalState
import org.matrix.TEESimulator.rka.journal.RkpJournalStore

class FreshBatchQuarantineLifecycleTest {
    @Test
    fun crashBeforeFirstActionLeavesActiveBatchAndResumeRunsEachEffectOnce() {
        val store = LifecycleStore()
        val journal = RkpJournal(store)
        val receipts = KeyedMemoryReceipts()
        val resources = CleanupResources()
        val batch = ByteArray(16) { 19 }
        val handle = preparePostAmbiguous(journal, batch, resources) {}
        var crash = true

        fun controller() =
            QuarantineController(
                exactQuarantine = {
                    if (crash) {
                        crash = false
                        throw IllegalStateException("crash before first action")
                    }
                    journal.quarantineHandles(it)
                },
                cancel = resources::cancel,
                cancelled = resources::cancelled,
                discard = resources::discard,
                discarded = resources::discarded,
                wipe = resources::wipe,
                wiped = resources::wiped,
                receipts = receipts,
                expectedBatch = { journal.recover()?.batchId?.copyBytes() },
                complete = journal::completeQuarantine,
                requireActiveBatch = true,
            )

        assertThrows(IllegalStateException::class.java) {
            controller().quarantine(request(119, batch, handle))
        }
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
        assertEquals(listOf(0, 0, 0), resources.effectCounts())
        assertEquals(
            QuarantineResult.QUARANTINED,
            controller().quarantine(request(119, batch, handle)),
        )
        assertEquals(listOf(1, 1, 1), resources.effectCounts())
    }

    @Test
    fun crashMatrixResumesWithoutRepeatingAnyExternalEffect() {
        CrashAction.entries.forEach { target ->
            val store = LifecycleStore()
            val journal = RkpJournal(store)
            val receipts = KeyedMemoryReceipts()
            val resources = CleanupResources()
            val batch = ByteArray(16) { (20 + target.ordinal).toByte() }
            val handle = preparePostAmbiguous(journal, batch, resources) {}
            var crash = true

            fun controller() =
                QuarantineController(
                    exactQuarantine = journal::quarantineHandles,
                    cancel = {
                        resources.cancel()
                        if (target == CrashAction.CANCEL && crash) {
                            crash = false
                            throw IllegalStateException("crash after cancel")
                        }
                    },
                    cancelled = resources::cancelled,
                    discard = {
                        resources.discard(it)
                        if (target == CrashAction.DISCARD && crash) {
                            crash = false
                            throw IllegalStateException("crash after discard")
                        }
                    },
                    discarded = resources::discarded,
                    wipe = {
                        resources.wipe(it)
                        if (target == CrashAction.WIPE && crash) {
                            crash = false
                            throw IllegalStateException("crash after wipe")
                        }
                    },
                    wiped = resources::wiped,
                    receipts = receipts,
                    expectedBatch = { journal.recover()?.batchId?.copyBytes() },
                    complete = journal::completeQuarantine,
                    requireActiveBatch = true,
                )

            assertThrows(IllegalStateException::class.java) {
                controller().quarantine(request(120 + target.ordinal.toLong(), batch, handle))
            }
            assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
            assertEquals(
                QuarantineResult.QUARANTINED,
                controller().quarantine(request(120 + target.ordinal.toLong(), batch, handle)),
            )
            assertEquals(listOf(1, 1, 1), resources.effectCounts())
            assertNull(store.read())
        }
    }

    @Test
    fun crashesAfterEachActionAckResumeAtTheNextUnacknowledgedAction() {
        (1..3).forEach { crashAfterCreate ->
            val store = LifecycleStore()
            val journal = RkpJournal(store)
            val receipts = CrashAfterCreateReceipts(crashAfterCreate)
            val resources = CleanupResources()
            val batch = ByteArray(16) { (30 + crashAfterCreate).toByte() }
            val handle = preparePostAmbiguous(journal, batch, resources) {}

            fun controller() =
                DonorProvisioningRuntime.buildQuarantineController(
                    journal,
                    receipts,
                    resources::cancel,
                    resources::cancelled,
                )

            assertThrows(IllegalStateException::class.java) {
                controller().quarantine(request(130 + crashAfterCreate.toLong(), batch, handle))
            }
            assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
            assertEquals(
                QuarantineResult.QUARANTINED,
                controller().quarantine(request(130 + crashAfterCreate.toLong(), batch, handle)),
            )
            assertEquals(listOf(1, 1, 1), resources.effectCounts())
            assertNull(store.read())
        }
    }

    @Test
    fun crashAfterCancelEffectBeforeDurableActionAckDoesNotRepeatCancel() {
        val store = LifecycleStore()
        val journal = RkpJournal(store)
        val receipts = KeyedMemoryReceipts()
        val batch = ByteArray(16) { 11 }
        val handle = preparePostAmbiguous(journal, batch) {}
        var cancelEffects = 0
        var cancelled = false
        var crashAfterEffect = true

        fun crashingController() =
            QuarantineController(
                exactQuarantine = journal::quarantineHandles,
                cancel = {
                    cancelEffects++
                    cancelled = true
                    if (crashAfterEffect) {
                        crashAfterEffect = false
                        throw IllegalStateException("crash after cancel effect")
                    }
                },
                cancelled = { cancelled },
                discard = {},
                wipe = {},
                receipts = receipts,
                expectedBatch = { journal.recover()?.batchId?.copyBytes() },
                complete = journal::completeQuarantine,
                requireActiveBatch = true,
            )

        assertThrows(IllegalStateException::class.java) {
            crashingController().quarantine(request(111, batch, handle))
        }
        assertEquals(
            QuarantineResult.QUARANTINED,
            crashingController().quarantine(request(111, batch, handle)),
        )
        assertEquals(1, cancelEffects)
    }

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
        assertEquals(8, receipts.count)
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
        assertEquals(4, receipts.count)

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
    fun missingOrTamperedActionAckWithCompletionTombstoneKeepsJournalBlocking() {
        listOf(false, true).forEach { tamper ->
            val store = LifecycleStore(failFirstClear = true)
            val journal = RkpJournal(store)
            val receipts = KeyedMemoryReceipts()
            val batch = ByteArray(16) { if (tamper) 41 else 42 }
            val handle = preparePostAmbiguous(journal, batch) {}
            var effects = 0
            val controller = controller(journal, receipts) { effects++ }

            assertThrows(IllegalStateException::class.java) {
                controller.quarantine(request(if (tamper) 141 else 142, batch, handle))
            }
            if (tamper) receipts.tamperFirst() else receipts.removeFirst()

            assertEquals(
                QuarantineResult.CLEANUP_INCOMPLETE,
                controller(journal, receipts) { effects++ }
                    .quarantine(request(if (tamper) 141 else 142, batch, handle)),
            )
            assertEquals(3, effects)
            assertEquals(RkpJournalState.DELETE, journal.recover()?.state)
            assertThrows(IllegalStateException::class.java) {
                journal.begin(count(), identity(), RkpBatchId.from(ByteArray(16) { 43 }))
            }
        }
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
        assertEquals(RkpJournalState.POST_AMBIGUOUS, journal.recover()?.state)
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
        resources: CleanupResources? = null,
        clear: () -> Unit,
    ): ByteArray {
        val generating = journal.begin(count(), identity(), RkpBatchId.from(batch))
        val entries = journal.deriveEntries(generating, listOf(byteArrayOf(batch[0]) to testSpki()))
        var current =
            journal.record(
                generating,
                entries,
                resolveBlob = { resources?.discarded(it) != true },
                discardBlob = resources?.let { it::discard },
                blobDiscarded = resources?.let { it::discarded },
                wipeBlob = resources?.let { it::wipe },
                blobWiped = resources?.let { it::wiped },
                clearBlobs = clear,
            )
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

private enum class CrashAction {
    CANCEL,
    DISCARD,
    WIPE,
}

private class CleanupResources {
    private var isCancelled = false
    private var isDiscarded = false
    private var isWiped = false
    private var cancelEffects = 0
    private var discardEffects = 0
    private var wipeEffects = 0

    fun cancel() {
        if (isCancelled) return
        isCancelled = true
        cancelEffects++
    }

    fun cancelled(): Boolean = isCancelled

    fun discard(@Suppress("UNUSED_PARAMETER") handle: ByteArray) {
        if (isDiscarded) return
        isDiscarded = true
        discardEffects++
    }

    fun discarded(@Suppress("UNUSED_PARAMETER") handle: ByteArray): Boolean = isDiscarded

    fun wipe(@Suppress("UNUSED_PARAMETER") handle: ByteArray) {
        if (isWiped) return
        check(isDiscarded)
        isWiped = true
        wipeEffects++
    }

    fun wiped(@Suppress("UNUSED_PARAMETER") handle: ByteArray): Boolean = isWiped

    fun effectCounts(): List<Int> = listOf(cancelEffects, discardEffects, wipeEffects)
}

private class CrashAfterCreateReceipts(private val crashAfterCreate: Int) : QuarantineReceiptStore {
    private val values = linkedMapOf<String, ByteArray>()
    private var creates = 0
    private var crashed = false

    override fun read(key: ByteArray): ByteArray? = values[key.hex()]?.copyOf()

    override fun create(key: ByteArray, receipt: ByteArray): Boolean {
        val name = key.hex()
        if (name in values) return false
        values[name] = receipt.copyOf()
        creates++
        if (!crashed && creates == crashAfterCreate) {
            crashed = true
            throw IllegalStateException("crash after durable action acknowledgement")
        }
        return true
    }
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

    fun removeFirst() {
        values.remove(values.keys.first())
    }

    fun tamperFirst() {
        values.values.first()[1] = (values.values.first()[1].toInt() xor 1).toByte()
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
