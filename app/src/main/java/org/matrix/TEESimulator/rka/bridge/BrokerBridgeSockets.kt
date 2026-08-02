package org.matrix.TEESimulator.rka.bridge

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.Closeable
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

internal interface BridgeServerBinding : Closeable {
    val socketNode: BridgeSocketNodeHandle

    fun acceptTransport(): BridgeTransport
}

internal fun interface BridgeServerBinder {
    fun bind(directory: BridgeSocketDirectoryHandle): BridgeResult<BridgeServerBinding>
}

private object AndroidBridgeServerBinder : BridgeServerBinder {
    override fun bind(directory: BridgeSocketDirectoryHandle): BridgeResult<BridgeServerBinding> {
        val bound = LocalSocket()
        var pendingNode: BridgeSocketNodeHandle? = null
        return try {
            bound.bind(
                LocalSocketAddress(
                    directory.anchoredSocketPath.toString(),
                    LocalSocketAddress.Namespace.FILESYSTEM,
                )
            )
            val openedNode = directory.openSocketNode()
            if (openedNode is BridgeResult.Failure) {
                bound.close()
                return openedNode
            }
            val node = (openedNode as BridgeResult.Success).value
            pendingNode = node
            val server = LocalServerSocket(bound.fileDescriptor)
            BridgeResult.Success(
                    object : BridgeServerBinding {
                        override val socketNode: BridgeSocketNodeHandle = node

                        override fun acceptTransport(): BridgeTransport =
                            AndroidLocalSocketTransport(server.accept())

                        override fun close() {
                            runCatching { server.close() }
                            runCatching { bound.close() }
                        }
                    }
                )
                .also { pendingNode = null }
        } catch (_: SecurityException) {
            pendingNode?.close()
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            pendingNode?.close()
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SocketBindDenied)
        }
    }
}

internal class DonorBridgeServer
private constructor(
    private val binding: BridgeServerBinding,
    private val directory: BridgeSocketDirectoryHandle,
    private val socketNode: BridgeSocketNodeHandle,
) : Closeable {
    internal fun nextTransport(): BridgeResult<BridgeTransport> =
        try {
            BridgeResult.Success(binding.acceptTransport())
        } catch (_: SecurityException) {
            BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            BridgeResult.Failure(BridgeError.SocketBindDenied)
        }

    internal fun socketMetadata(): SocketMetadata =
        when (socketNode.inspect()) {
            is BridgeResult.Success -> SocketMetadata.secureRootOwned()
            is BridgeResult.Failure -> SocketMetadata.insecure()
        }

    override fun close() {
        runCatching { binding.close() }
        socketNode.deleteIfStillNamed()
        socketNode.close()
        directory.close()
    }

    internal companion object {
        fun bind(): BridgeResult<DonorBridgeServer> =
            bind(SecureSocketPath(), AndroidBridgeServerBinder)

        fun bind(
            pathSecurity: SecureSocketPath,
            binder: BridgeServerBinder,
        ): BridgeResult<DonorBridgeServer> {
            val opened = pathSecurity.open()
            if (opened is BridgeResult.Failure) return opened
            return bindOpened((opened as BridgeResult.Success).value, binder)
        }

        fun bind(
            socketPath: Path,
            pathSecurity: SecureSocketPath,
            binder: BridgeServerBinder,
        ): BridgeResult<DonorBridgeServer> {
            val opened = pathSecurity.open(socketPath)
            if (opened is BridgeResult.Failure) return opened
            return bindOpened((opened as BridgeResult.Success).value, binder)
        }

        private fun bindOpened(
            directory: BridgeSocketDirectoryHandle,
            binder: BridgeServerBinder,
        ): BridgeResult<DonorBridgeServer> {
            val bound = binder.bind(directory)
            if (bound is BridgeResult.Failure) {
                directory.close()
                return bound
            }
            val binding = (bound as BridgeResult.Success).value
            val node = binding.socketNode
            val chowned = node.chownRoot()
            if (chowned is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, chowned)
            }
            val afterChown = node.verifyStillNamed()
            if (afterChown is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, afterChown, delete = false)
            }
            val chmodded = node.chmodOwnerOnly()
            if (chmodded is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, chmodded)
            }
            val afterChmod = node.verifyStillNamed()
            if (afterChmod is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, afterChmod, delete = false)
            }
            val labeled = node.labelDedicatedContext()
            if (labeled is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, labeled)
            }
            val afterLabel = node.verifyStillNamed()
            if (afterLabel is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, afterLabel, delete = false)
            }
            val context = node.verifyDedicatedContext()
            if (context is BridgeResult.Failure) {
                return failAfterBind(binding, directory, node, context)
            }
            if (node.inspect() is BridgeResult.Failure) {
                return failAfterBind(
                    binding,
                    directory,
                    node,
                    BridgeResult.Failure(BridgeError.SocketPathChanged),
                )
            }
            return BridgeResult.Success(DonorBridgeServer(binding, directory, node))
        }

        private fun failAfterBind(
            binding: BridgeServerBinding,
            directory: BridgeSocketDirectoryHandle,
            node: BridgeSocketNodeHandle,
            failure: BridgeResult.Failure,
            delete: Boolean = true,
        ): BridgeResult.Failure {
            runCatching { binding.close() }
            if (delete) node.deleteIfStillNamed()
            node.close()
            directory.close()
            return failure
        }
    }
}

internal object CandidateBridgeConnector {
    fun boundedTransport(): BridgeTransport {
        val pending = AtomicReference<LocalSocket>()
        return DeferredBridgeTransport(
            factory = {
                val opened = SecureSocketPath().open()
                if (opened is BridgeResult.Failure) {
                    throw BridgeTransportException(opened.error)
                }
                val directory = (opened as BridgeResult.Success).value
                val openedNode = directory.openSocketNode()
                if (openedNode is BridgeResult.Failure) {
                    directory.close()
                    throw BridgeTransportException(openedNode.error)
                }
                val node = (openedNode as BridgeResult.Success).value
                val before = node.inspect()
                if (before is BridgeResult.Failure) {
                    node.close()
                    directory.close()
                    throw BridgeTransportException(before.error)
                }
                val socket = LocalSocket()
                pending.set(socket)
                try {
                    socket.connect(
                        LocalSocketAddress(
                            directory.anchoredSocketPath.toString(),
                            LocalSocketAddress.Namespace.FILESYSTEM,
                        )
                    )
                    if (node.verifyStillNamed() is BridgeResult.Failure) {
                        throw BridgeTransportException(BridgeError.SocketPathChanged)
                    }
                    HeldSocketTransport(AndroidLocalSocketTransport(socket), node, directory)
                } catch (error: BridgeTransportException) {
                    runCatching { socket.close() }
                    node.close()
                    directory.close()
                    throw error
                } catch (_: SecurityException) {
                    runCatching { socket.close() }
                    node.close()
                    directory.close()
                    throw BridgeTransportException(BridgeError.SelinuxDenied)
                } catch (_: Exception) {
                    runCatching { socket.close() }
                    node.close()
                    directory.close()
                    throw BridgeTransportException(BridgeError.SocketBindDenied)
                }
            },
            abortPending = { runCatching { pending.get()?.close() } },
        )
    }
}

private class HeldSocketTransport(
    private val delegate: BridgeTransport,
    private val node: BridgeSocketNodeHandle,
    private val directory: BridgeSocketDirectoryHandle,
) : BridgeTransport by delegate {
    override fun close() {
        runCatching { delegate.close() }
        node.close()
        directory.close()
    }
}
