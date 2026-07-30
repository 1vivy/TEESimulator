package org.matrix.TEESimulator.rka.bridge

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask

internal class BridgeTransportException(val error: BridgeError) : RuntimeException()

internal class DeferredBridgeTransport(
    factory: () -> BridgeTransport,
    private val abortPending: () -> Unit,
) : BridgeTransport {
    private val task = FutureTask(factory)

    override fun peerCredentials(): PeerCredentials = transport().peerCredentials()

    override fun input(): InputStream = transport().input()

    override fun output(): OutputStream = transport().output()

    override fun close() {
        abortPending()
        task.cancel(true)
        if (task.isDone && !task.isCancelled) runCatching { task.get().close() }
    }

    private fun transport(): BridgeTransport {
        task.run()
        return try {
            task.get()
        } catch (error: ExecutionException) {
            val cause = error.cause
            if (cause is BridgeTransportException) throw cause
            throw BridgeTransportException(BridgeError.SocketBindDenied)
        }
    }
}
