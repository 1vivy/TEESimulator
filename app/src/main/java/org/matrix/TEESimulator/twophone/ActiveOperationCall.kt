package org.matrix.TEESimulator.twophone

import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

internal class ActiveOperationCall {
    private val ownership = AtomicReference(Ownership())

    val operationId: UUID?
        get() = ownership.get().operationId

    fun publish(
        cancellation: TargetCallCancellation,
        ownerDeathAbortOperationId: UUID?,
    ) {
        while (true) {
            val current = ownership.get()
            if (current.ownerDead && current.operationId != ownerDeathAbortOperationId) {
                cancellation.cancel()
                throw TargetSessionException.Cancelled()
            }
            if (ownership.compareAndSet(current, current.copy(cancellation = cancellation))) return
        }
    }

    fun clearCall(cancellation: TargetCallCancellation) {
        update { current ->
            if (current.cancellation !== cancellation) current
            else current.copy(cancellation = null)
        }
    }

    fun markOwnerDead(expectedOperationId: UUID): Boolean {
        while (true) {
            val current = ownership.get()
            if (current.operationId != expectedOperationId) return false
            if (!ownership.compareAndSet(current, current.copy(ownerDead = true))) continue
            current.cancellation?.cancel()
            return current.cancellation != null
        }
    }

    fun begin(operationId: UUID?) {
        update { it.copy(operationId = operationId, ownerDead = false) }
    }

    fun complete() {
        update { it.copy(operationId = null, ownerDead = false) }
    }

    fun clear(expectedOperationId: UUID): Boolean {
        while (true) {
            val current = ownership.get()
            if (current.operationId != expectedOperationId) return false
            if (ownership.compareAndSet(current, Ownership())) return true
        }
    }

    fun clear() {
        ownership.set(Ownership())
    }

    private inline fun update(transform: (Ownership) -> Ownership) {
        while (true) {
            val current = ownership.get()
            val updated = transform(current)
            if (updated === current || ownership.compareAndSet(current, updated)) return
        }
    }

    private data class Ownership(
        val operationId: UUID? = null,
        val cancellation: TargetCallCancellation? = null,
        val ownerDead: Boolean = false,
    )
}
