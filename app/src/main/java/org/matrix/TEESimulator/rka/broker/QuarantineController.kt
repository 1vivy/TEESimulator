package org.matrix.TEESimulator.rka.broker

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.matrix.TEESimulator.rka.bridge.BrokerBatchId
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.RequestId

class AuthenticatedQuarantineRequest
private constructor(
    val requestId: RequestId,
    val batchId: ByteArray,
    handles: List<ByteArray>,
    actionIds: List<ByteArray>,
) : AutoCloseable {
    private val handles = handles.map(ByteArray::copyOf)
    private val actionIds = actionIds.map(ByteArray::copyOf)

    internal fun copyHandles(): List<ByteArray> = handles.map(ByteArray::copyOf)

    internal fun copyActionIds(): List<ByteArray> = actionIds.map(ByteArray::copyOf)

    internal fun receipt(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("TEESimulator-RS quarantine receipt v1\u0000".toByteArray())
        actionIds.forEach(digest::update)
        return digest.digest()
    }

    internal fun receiptKey(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("TEESimulator-RS quarantine receipt key v1\u0000".toByteArray())
        digest.update(
            ByteBuffer.allocate(Long.SIZE_BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(requestId.value)
                .array()
        )
        digest.update(batchId)
        actionIds.forEach(digest::update)
        return digest.digest()
    }

    override fun close() {
        batchId.fill(0)
        handles.forEach { it.fill(0) }
        actionIds.forEach { it.fill(0) }
    }

    companion object {
        internal fun fromTrustedBridge(
            requestId: RequestId,
            handles: List<ByteArray>,
        ): AuthenticatedQuarantineRequest {
            val batchId = ByteArray(16)
            val actionIds = deriveActionIds(requestId, batchId, handles)
            return AuthenticatedQuarantineRequest(requestId, batchId, handles, actionIds)
        }

        internal fun fromTrustedBridge(
            requestId: RequestId,
            handles: List<ByteArray>,
            batchId: BrokerBatchId,
            actionIds: List<Hash32>,
        ): AuthenticatedQuarantineRequest {
            require(requestId.value != 0L)
            require(handles.isNotEmpty() && handles.size <= RkpKeyCount.MAX)
            require(handles.all { it.size == 32 })
            require(
                handles.indices.all { index ->
                    handles.drop(index + 1).none(handles[index]::contentEquals)
                }
            )
            val batchBytes = batchId.copyBytes()
            val supplied = actionIds.map(Hash32::copyBytes)
            val expected = deriveActionIds(requestId, batchBytes, handles)
            require(supplied.size == expected.size)
            require(supplied.zip(expected).all { (actual, value) -> actual.contentEquals(value) })
            expected.forEach { it.fill(0) }
            return AuthenticatedQuarantineRequest(requestId, batchBytes, handles, supplied)
        }

        private fun deriveActionIds(
            requestId: RequestId,
            batchId: ByteArray,
            handles: List<ByteArray>,
        ): List<ByteArray> {
            fun derive(tag: Int, handle: ByteArray?): ByteArray {
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update("TEESimulator-RS quarantine action v1\u0000".toByteArray())
                digest.update(
                    ByteBuffer.allocate(Long.SIZE_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putLong(requestId.value)
                        .array()
                )
                digest.update(batchId)
                digest.update(tag.toByte())
                handle?.let(digest::update)
                return digest.digest()
            }
            return buildList {
                add(derive(0, null))
                handles.forEach { handle ->
                    add(derive(1, handle))
                    add(derive(2, handle))
                }
            }
        }
    }
}

internal interface QuarantineReceiptStore {
    fun read(key: ByteArray): ByteArray?

    fun create(key: ByteArray, receipt: ByteArray): Boolean
}

private class MemoryQuarantineReceiptStore : QuarantineReceiptStore {
    private val receipts = linkedMapOf<String, ByteArray>()

    override fun read(key: ByteArray): ByteArray? = receipts[key.hex()]?.copyOf()

    override fun create(key: ByteArray, receipt: ByteArray): Boolean {
        val name = key.hex()
        if (name in receipts || receipts.size >= MAX_RECEIPTS) return false
        receipts[name] = receipt.copyOf()
        return true
    }

    private companion object {
        const val MAX_RECEIPTS = 128
    }
}

enum class QuarantineResult {
    QUARANTINED,
    HANDLE_MISMATCH,
    ALREADY_QUARANTINED,
    CLEANUP_INCOMPLETE,
}

class QuarantineController
internal constructor(
    private val exactQuarantine: (List<ByteArray>) -> Boolean,
    private val cancel: () -> Unit,
    private val cancelled: () -> Boolean = { false },
    private val discard: (ByteArray) -> Unit,
    private val discarded: (ByteArray) -> Boolean = { false },
    private val wipe: (ByteArray) -> Unit,
    private val wiped: (ByteArray) -> Boolean = { false },
    private val receipts: QuarantineReceiptStore = MemoryQuarantineReceiptStore(),
    private val expectedBatch: () -> ByteArray? = { null },
    private val complete: (ByteArray) -> Boolean = { true },
    private val requireActiveBatch: Boolean = false,
) {
    private val terminalRequests = mutableSetOf<RequestId>()
    private var allActivationClosed = false
    private var retained = false

    @Synchronized
    fun quarantine(request: AuthenticatedQuarantineRequest): QuarantineResult =
        request.use {
            val key = request.receiptKey()
            val receipt = request.receipt()
            val stored = receipts.read(key)
            if (stored != null) {
                val result = replayResult(stored, receipt)
                stored.fill(0)
                if (result == null) return QuarantineResult.HANDLE_MISMATCH
                if (!allActionReceiptsPresent(request)) {
                    receipt.fill(0)
                    key.fill(0)
                    return QuarantineResult.CLEANUP_INCOMPLETE
                }
                receipt.fill(0)
                key.fill(0)
                if (!complete(request.batchId)) {
                    return QuarantineResult.CLEANUP_INCOMPLETE
                }
                return result
            }
            val expected = expectedBatch()
            if (expected == null && requireActiveBatch) {
                receipt.fill(0)
                key.fill(0)
                return QuarantineResult.HANDLE_MISMATCH
            }
            if (expected != null) {
                val matches = expected.contentEquals(request.batchId)
                expected.fill(0)
                if (!matches) {
                    receipt.fill(0)
                    key.fill(0)
                    return QuarantineResult.HANDLE_MISMATCH
                }
            }
            val handles = request.copyHandles()
            try {
                val exact = exactQuarantine(handles)
                retained = true
                if (terminalRequests.size < MAX_TERMINAL_REQUESTS) {
                    terminalRequests += request.requestId
                } else {
                    terminalRequests.clear()
                    allActivationClosed = true
                }
                val actionIds = request.copyActionIds()
                try {
                    when (durableAction(actionIds[0], cancelled, cancel)) {
                        DurableActionResult.COMPLETE -> Unit
                        DurableActionResult.TAMPERED -> return QuarantineResult.HANDLE_MISMATCH
                        DurableActionResult.INCOMPLETE -> return QuarantineResult.CLEANUP_INCOMPLETE
                    }
                    handles.forEachIndexed { index, handle ->
                        val discardId = actionIds[1 + index * 2]
                        when (
                            durableAction(discardId, { discarded(handle) }, { discard(handle) })
                        ) {
                            DurableActionResult.COMPLETE -> Unit
                            DurableActionResult.TAMPERED -> return QuarantineResult.HANDLE_MISMATCH
                            DurableActionResult.INCOMPLETE ->
                                return QuarantineResult.CLEANUP_INCOMPLETE
                        }
                        val wipeId = actionIds[2 + index * 2]
                        when (durableAction(wipeId, { wiped(handle) }, { wipe(handle) })) {
                            DurableActionResult.COMPLETE -> Unit
                            DurableActionResult.TAMPERED -> return QuarantineResult.HANDLE_MISMATCH
                            DurableActionResult.INCOMPLETE ->
                                return QuarantineResult.CLEANUP_INCOMPLETE
                        }
                        handle.fill(0)
                    }
                } finally {
                    actionIds.forEach { it.fill(0) }
                }
                val storedReceipt = byteArrayOf(if (exact) 1 else 0) + receipt
                val created = receipts.create(key, storedReceipt)
                storedReceipt.fill(0)
                if (!created) {
                    val raced = receipts.read(key) ?: return QuarantineResult.CLEANUP_INCOMPLETE
                    val matches = replayResult(raced, receipt) != null
                    raced.fill(0)
                    if (!matches) return QuarantineResult.HANDLE_MISMATCH
                }
                if (!complete(request.batchId)) return QuarantineResult.CLEANUP_INCOMPLETE
                return if (exact) {
                    QuarantineResult.QUARANTINED
                } else {
                    QuarantineResult.HANDLE_MISMATCH
                }
            } finally {
                receipt.fill(0)
                key.fill(0)
                handles.forEach { it.fill(0) }
            }
        }

    private fun allActionReceiptsPresent(request: AuthenticatedQuarantineRequest): Boolean =
        request.copyActionIds().let { actionIds ->
            try {
                actionIds.all { actionId ->
                    val key = actionReceiptKey(actionId)
                    val expected = actionReceipt(actionId)
                    val stored = receipts.read(key)
                    try {
                        stored != null && stored.contentEquals(expected)
                    } finally {
                        key.fill(0)
                        expected.fill(0)
                        stored?.fill(0)
                    }
                }
            } finally {
                actionIds.forEach { it.fill(0) }
            }
        }

    private fun durableAction(
        actionId: ByteArray,
        completed: () -> Boolean,
        effect: () -> Unit,
    ): DurableActionResult {
        val key = actionReceiptKey(actionId)
        val expected = actionReceipt(actionId)
        try {
            val stored = receipts.read(key)
            if (stored != null) {
                val matches = stored.contentEquals(expected)
                stored.fill(0)
                return if (matches) {
                    DurableActionResult.COMPLETE
                } else {
                    DurableActionResult.TAMPERED
                }
            }
            if (!completed()) effect()
            if (receipts.create(key, expected)) return DurableActionResult.COMPLETE
            val raced = receipts.read(key) ?: return DurableActionResult.INCOMPLETE
            val matches = raced.contentEquals(expected)
            raced.fill(0)
            return if (matches) DurableActionResult.COMPLETE else DurableActionResult.TAMPERED
        } finally {
            key.fill(0)
            expected.fill(0)
        }
    }

    private fun actionReceiptKey(actionId: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("TEESimulator-RS quarantine action receipt key v1\u0000".toByteArray())
        digest.update(actionId)
        return digest.digest()
    }

    private fun actionReceipt(actionId: ByteArray): ByteArray =
        byteArrayOf(ACTION_RECEIPT_VERSION) + actionId

    private fun replayResult(stored: ByteArray, receipt: ByteArray): QuarantineResult? {
        val replay =
            stored.size == receipt.size + 1 &&
                stored.copyOfRange(1, stored.size).contentEquals(receipt)
        if (!replay) return null
        return if (stored.firstOrNull() == 1.toByte()) {
            QuarantineResult.QUARANTINED
        } else {
            QuarantineResult.HANDLE_MISMATCH
        }
    }

    @Synchronized
    fun activationAllowed(requestId: RequestId): Boolean =
        !allActivationClosed && requestId !in terminalRequests

    @Synchronized fun quarantineRetained(): Boolean = retained

    private companion object {
        const val MAX_TERMINAL_REQUESTS = 64
        const val ACTION_RECEIPT_VERSION = 1.toByte()
    }
}

private enum class DurableActionResult {
    COMPLETE,
    TAMPERED,
    INCOMPLETE,
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
