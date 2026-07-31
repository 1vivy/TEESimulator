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

    internal fun receipt(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("TEESimulator-RS quarantine receipt v1\u0000".toByteArray())
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
            require(requestId.value > 0)
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
    fun read(): ByteArray?

    fun replace(receipt: ByteArray)
}

private class MemoryQuarantineReceiptStore : QuarantineReceiptStore {
    private var receipt: ByteArray? = null

    override fun read(): ByteArray? = receipt?.copyOf()

    override fun replace(receipt: ByteArray) {
        this.receipt = receipt.copyOf()
    }
}

enum class QuarantineResult {
    QUARANTINED,
    HANDLE_MISMATCH,
    ALREADY_QUARANTINED,
}

class QuarantineController
internal constructor(
    private val exactQuarantine: (List<ByteArray>) -> Boolean,
    private val cancel: () -> Unit,
    private val discard: (ByteArray) -> Unit = {},
    private val wipe: (ByteArray) -> Unit = {},
    private val receipts: QuarantineReceiptStore = MemoryQuarantineReceiptStore(),
    private val expectedBatch: () -> ByteArray? = { null },
) {
    private var terminalRequest: RequestId? = null
    private var retained = false

    @Synchronized
    fun quarantine(request: AuthenticatedQuarantineRequest): QuarantineResult =
        request.use {
            val expected = expectedBatch()
            if (expected != null) {
                val matches = expected.contentEquals(request.batchId)
                expected.fill(0)
                if (!matches) return QuarantineResult.HANDLE_MISMATCH
            }
            val receipt = request.receipt()
            val stored = receipts.read()
            if (stored != null) {
                val replay =
                    stored.size == receipt.size + 1 &&
                        stored.copyOfRange(1, stored.size).contentEquals(receipt)
                val outcome = stored.firstOrNull()
                stored.fill(0)
                receipt.fill(0)
                if (!replay) return QuarantineResult.HANDLE_MISMATCH
                return if (outcome == 1.toByte()) {
                    QuarantineResult.QUARANTINED
                } else {
                    QuarantineResult.HANDLE_MISMATCH
                }
            }
            val handles = request.copyHandles()
            try {
                val exact = exactQuarantine(handles)
                retained = true
                terminalRequest = request.requestId
                cancel()
                handles.forEach { handle ->
                    discard(handle.copyOf())
                    wipe(handle)
                    handle.fill(0)
                }
                receipts.replace(byteArrayOf(if (exact) 1 else 0) + receipt)
                if (exact) QuarantineResult.QUARANTINED else QuarantineResult.HANDLE_MISMATCH
            } finally {
                receipt.fill(0)
                handles.forEach { it.fill(0) }
            }
        }

    @Synchronized
    fun activationAllowed(requestId: RequestId): Boolean = terminalRequest != requestId

    @Synchronized fun quarantineRetained(): Boolean = retained
}
