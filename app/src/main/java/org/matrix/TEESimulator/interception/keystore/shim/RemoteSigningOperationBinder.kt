package org.matrix.TEESimulator.interception.keystore.shim

import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.matrix.TEESimulator.interception.core.OriginProcessDeathLease
import org.matrix.TEESimulator.twophone.RemoteSigningOperation

internal class RemoteSigningOperationBinder(
    private val operation: RemoteSigningOperation,
    originDeathLease: OriginProcessDeathLease,
) : IKeystoreOperation.Stub() {
    private val terminal = AtomicBoolean(false)
    private val originDeathWatchRef = AtomicReference<AutoCloseable?>()

    init {
        try {
            originDeathLease.claim(::onOriginDeath).also { watch ->
                originDeathWatchRef.set(watch)
                if (terminal.get()) closeOriginDeathWatch()
            }
        } catch (failure: RuntimeException) {
            runCatching(originDeathLease::close)
            runCatching(operation::abort)
            throw failure
        }
    }

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? = remote {
        operation.update(input ?: ByteArray(0))
    }

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) {
        try {
            remote { operation.abort() }
        } finally {
            closeTerminal()
        }
        throw RemoteException("UPDATE_AAD is unsupported for remote signing operations")
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        if (signature != null) {
            try {
                remote { operation.abort() }
            } finally {
                closeTerminal()
            }
            throw RemoteException("remote signing operations do not accept a signature")
        }
        return remote { operation.finish(input ?: ByteArray(0)) }.also { closeTerminal() }
    }

    @Throws(RemoteException::class)
    override fun abort() {
        try {
            remote { operation.abort() }
        } finally {
            closeTerminal()
        }
    }

    private inline fun <T> remote(block: () -> T): T =
        try {
            block()
        } catch (failure: RuntimeException) {
            closeTerminal()
            throw RemoteException(failure.message).also { it.initCause(failure) }
        }

    private fun onOriginDeath() {
        if (!terminal.compareAndSet(false, true)) return
        try {
            operation.abortFromOwnerDeath()
        } finally {
            closeOriginDeathWatch()
        }
    }

    private fun closeTerminal() {
        if (terminal.compareAndSet(false, true)) closeOriginDeathWatch()
    }

    private fun closeOriginDeathWatch() {
        originDeathWatchRef.getAndSet(null)?.close()
    }
}
