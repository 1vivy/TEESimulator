package org.matrix.TEESimulator.rka.broker

import org.matrix.TEESimulator.rka.bridge.RequestId

class AuthenticatedQuarantineRequest
private constructor(val requestId: RequestId, handles: List<ByteArray>) : AutoCloseable {
    private val handles = handles.map(ByteArray::copyOf)

    internal fun copyHandles(): List<ByteArray> = handles.map(ByteArray::copyOf)

    override fun close() = handles.forEach { it.fill(0) }

    companion object {
        internal fun fromTrustedBridge(
            requestId: RequestId,
            handles: List<ByteArray>,
        ): AuthenticatedQuarantineRequest {
            require(requestId.value > 0)
            require(handles.isNotEmpty() && handles.size <= RkpKeyCount.MAX)
            require(handles.all { it.size == 32 })
            require(
                handles.indices.all { index ->
                    handles.drop(index + 1).none(handles[index]::contentEquals)
                }
            )
            return AuthenticatedQuarantineRequest(requestId, handles)
        }
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
) {
    private var terminalRequest: RequestId? = null
    private var retained = false

    @Synchronized
    fun quarantine(request: AuthenticatedQuarantineRequest): QuarantineResult =
        request.use {
            if (terminalRequest != null) return QuarantineResult.ALREADY_QUARANTINED
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
                if (exact) QuarantineResult.QUARANTINED else QuarantineResult.HANDLE_MISMATCH
            } finally {
                handles.forEach { it.fill(0) }
            }
        }

    @Synchronized
    fun activationAllowed(requestId: RequestId): Boolean = terminalRequest != requestId

    @Synchronized fun quarantineRetained(): Boolean = retained
}
