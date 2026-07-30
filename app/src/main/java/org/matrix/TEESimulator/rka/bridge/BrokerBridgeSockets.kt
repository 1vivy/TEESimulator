package org.matrix.TEESimulator.rka.bridge

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.Closeable
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

internal interface BridgeServerBinding : Closeable {
    fun accept(): BridgeTransport
}

internal fun interface BridgeServerBinder {
    fun bind(socketPath: Path): BridgeResult<BridgeServerBinding>
}

private object AndroidBridgeServerBinder : BridgeServerBinder {
    override fun bind(socketPath: Path): BridgeResult<BridgeServerBinding> {
        val bound = LocalSocket()
        return try {
            bound.bind(
                LocalSocketAddress(socketPath.toString(), LocalSocketAddress.Namespace.FILESYSTEM)
            )
            val server = LocalServerSocket(bound.fileDescriptor)
            BridgeResult.Success(
                object : BridgeServerBinding {
                    override fun accept(): BridgeTransport =
                        AndroidLocalSocketTransport(server.accept())

                    override fun close() {
                        server.close()
                        bound.close()
                    }
                }
            )
        } catch (_: SecurityException) {
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SocketBindDenied)
        }
    }
}

class DonorBridgeServer
private constructor(
    private val binding: BridgeServerBinding,
    private val socketPath: Path,
    private val socketInode: Long,
    private val pathSecurity: SecureSocketPath,
) : Closeable {
    fun accept(): BridgeTransport = binding.accept()

    fun deferredAccept(): BridgeTransport =
        DeferredBridgeTransport(
            factory = binding::accept,
            abortPending = { runCatching { binding.close() } },
        )

    override fun close() {
        runCatching { binding.close() }
        pathSecurity.deleteExact(socketPath, socketInode)
    }

    companion object {
        fun bind(socketPath: Path): BridgeResult<DonorBridgeServer> =
            bind(socketPath, SecureSocketPath(), AndroidBridgeServerBinder)

        internal fun bind(
            socketPath: Path,
            pathSecurity: SecureSocketPath,
            binder: BridgeServerBinder,
        ): BridgeResult<DonorBridgeServer> {
            val prepared = pathSecurity.prepare(socketPath)
            if (prepared is BridgeResult.Failure) return prepared
            val directory = (prepared as BridgeResult.Success).value
            val bound = binder.bind(socketPath)
            if (bound is BridgeResult.Failure) {
                pathSecurity.cleanupNewSocket(socketPath)
                return bound
            }
            val binding = (bound as BridgeResult.Success).value
            val secured = pathSecurity.secureBoundSocket(directory, socketPath)
            if (secured is BridgeResult.Failure) {
                runCatching { binding.close() }
                pathSecurity.cleanupNewSocket(socketPath)
                return secured
            }
            return BridgeResult.Success(
                DonorBridgeServer(
                    binding,
                    socketPath,
                    (secured as BridgeResult.Success).value,
                    pathSecurity,
                )
            )
        }
    }
}

object CandidateBridgeConnector {
    fun deferredConnect(socketPath: Path): BridgeTransport {
        val pending = AtomicReference<LocalSocket>()
        return DeferredBridgeTransport(
            factory = {
                val socket = LocalSocket()
                pending.set(socket)
                when (val connected = connect(socketPath, socket)) {
                    is BridgeResult.Success -> connected.value
                    is BridgeResult.Failure -> throw BridgeTransportException(connected.error)
                }
            },
            abortPending = { runCatching { pending.get()?.close() } },
        )
    }

    fun connect(socketPath: Path): BridgeResult<BridgeTransport> =
        connect(socketPath, LocalSocket())

    private fun connect(socketPath: Path, socket: LocalSocket): BridgeResult<BridgeTransport> {
        val pathSecurity = SecureSocketPath()
        val prepared = pathSecurity.prepare(socketPath, requireAbsentSocket = false)
        if (prepared is BridgeResult.Failure) return prepared
        val secured =
            pathSecurity.secureBoundSocket((prepared as BridgeResult.Success).value, socketPath)
        if (secured is BridgeResult.Failure) return secured
        val expectedInode = (secured as BridgeResult.Success).value
        return try {
            socket.connect(
                LocalSocketAddress(socketPath.toString(), LocalSocketAddress.Namespace.FILESYSTEM)
            )
            val rechecked = pathSecurity.secureBoundSocket(prepared.value, socketPath)
            if (rechecked !is BridgeResult.Success || rechecked.value != expectedInode) {
                runCatching { socket.close() }
                BridgeResult.Failure(BridgeError.SocketPathChanged)
            } else {
                BridgeResult.Success(AndroidLocalSocketTransport(socket))
            }
        } catch (_: SecurityException) {
            runCatching { socket.close() }
            BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            runCatching { socket.close() }
            BridgeResult.Failure(BridgeError.SocketBindDenied)
        }
    }
}
