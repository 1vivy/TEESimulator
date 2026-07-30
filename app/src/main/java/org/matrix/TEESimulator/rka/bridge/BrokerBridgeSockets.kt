package org.matrix.TEESimulator.rka.bridge

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.FileDescriptor
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

internal interface BridgeServerBinding : Closeable {
    fun acceptTransport(): BridgeTransport

    fun boundSocketInode(): Long

    fun chownBoundSocket(inode: Long): BridgeResult<Unit>

    fun chmodBoundSocket(inode: Long): BridgeResult<Unit>
}

internal fun interface BridgeServerBinder {
    fun bind(socketPath: Path): BridgeResult<BridgeServerBinding>
}

private object AndroidBridgeServerBinder : BridgeServerBinder {
    override fun bind(socketPath: Path): BridgeResult<BridgeServerBinding> {
        val bound = LocalSocket()
        var pendingPathDescriptor: FileDescriptor? = null
        return try {
            bound.bind(
                LocalSocketAddress(socketPath.toString(), LocalSocketAddress.Namespace.FILESYSTEM)
            )
            val pathDescriptor =
                Os.open(
                    socketPath.toString(),
                    O_PATH or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                    0,
                )
            pendingPathDescriptor = pathDescriptor
            val pathStat = Os.fstat(pathDescriptor)
            if (pathStat.st_mode and OsConstants.S_IFMT != OsConstants.S_IFSOCK) {
                Os.close(pathDescriptor)
                pendingPathDescriptor = null
                bound.close()
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
            val inode = pathStat.st_ino
            val descriptorPath = "/proc/self/fd/${descriptorNumber(pathDescriptor)}"
            val server = LocalServerSocket(bound.fileDescriptor)
            BridgeResult.Success(
                    object : BridgeServerBinding {
                        override fun acceptTransport(): BridgeTransport =
                            AndroidLocalSocketTransport(server.accept())

                        override fun boundSocketInode(): Long = inode

                        override fun chownBoundSocket(inode: Long): BridgeResult<Unit> {
                            if (Os.fstat(pathDescriptor).st_ino != inode) {
                                return BridgeResult.Failure(BridgeError.SocketPathChanged)
                            }
                            try {
                                Os.chown(descriptorPath, 0, 0)
                            } catch (_: Exception) {
                                return BridgeResult.Failure(BridgeError.SocketChownDenied)
                            }
                            val after = Os.fstat(pathDescriptor)
                            return if (
                                after.st_ino == inode &&
                                    after.st_uid == 0 &&
                                    after.st_gid == 0 &&
                                    after.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK
                            ) {
                                BridgeResult.Success(Unit)
                            } else {
                                BridgeResult.Failure(BridgeError.SocketPathChanged)
                            }
                        }

                        override fun chmodBoundSocket(inode: Long): BridgeResult<Unit> {
                            if (Os.fstat(pathDescriptor).st_ino != inode) {
                                return BridgeResult.Failure(BridgeError.SocketPathChanged)
                            }
                            try {
                                Os.chmod(descriptorPath, 0x180)
                            } catch (_: Exception) {
                                return BridgeResult.Failure(BridgeError.SocketChmodDenied)
                            }
                            val after = Os.fstat(pathDescriptor)
                            return if (
                                after.st_ino == inode &&
                                    after.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK &&
                                    after.st_mode and 0x1ff == 0x180
                            ) {
                                BridgeResult.Success(Unit)
                            } else {
                                BridgeResult.Failure(BridgeError.SocketPathChanged)
                            }
                        }

                        override fun close() {
                            runCatching { server.close() }
                            runCatching { bound.close() }
                            runCatching { Os.close(pathDescriptor) }
                        }
                    }
                )
                .also { pendingPathDescriptor = null }
        } catch (_: SecurityException) {
            pendingPathDescriptor?.let { runCatching { Os.close(it) } }
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            pendingPathDescriptor?.let { runCatching { Os.close(it) } }
            runCatching { bound.close() }
            BridgeResult.Failure(BridgeError.SocketBindDenied)
        }
    }

    private fun descriptorNumber(descriptor: FileDescriptor): Int =
        FileDescriptor::class.java.getDeclaredMethod("getInt$").invoke(descriptor) as Int

    private const val O_PATH = 0x200000
}

internal class DonorBridgeServer
private constructor(
    private val binding: BridgeServerBinding,
    private val directory: BridgeSocketDirectoryHandle,
    private val socketInode: Long,
) : Closeable {
    internal fun boundedTransport(): BridgeTransport =
        DeferredBridgeTransport(
            factory = binding::acceptTransport,
            abortPending = { runCatching { binding.close() } },
        )

    internal fun socketMetadata(): SocketMetadata =
        when (val inspected = directory.inspectSocket()) {
            is BridgeResult.Success ->
                if (inspected.value.inode == socketInode) {
                    SocketMetadata.secureRootOwned()
                } else {
                    SocketMetadata.insecure()
                }
            is BridgeResult.Failure -> SocketMetadata.insecure()
        }

    override fun close() {
        runCatching { binding.close() }
        directory.deleteExactSocket(socketInode)
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
            val bound = binder.bind(directory.anchoredSocketPath)
            if (bound is BridgeResult.Failure) {
                directory.close()
                return bound
            }
            val binding = (bound as BridgeResult.Success).value
            val inode =
                try {
                    binding.boundSocketInode()
                } catch (_: Exception) {
                    runCatching { binding.close() }
                    directory.close()
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
            val verified = directory.verifySocketInode(inode)
            if (verified is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.close()
                return verified
            }
            val chowned = binding.chownBoundSocket(inode)
            if (chowned is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.deleteExactSocket(inode)
                directory.close()
                return chowned
            }
            val afterChown = directory.verifySocketInode(inode)
            if (afterChown is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.close()
                return afterChown
            }
            val chmodded = binding.chmodBoundSocket(inode)
            if (chmodded is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.deleteExactSocket(inode)
                directory.close()
                return chmodded
            }
            val afterChmod = directory.verifySocketInode(inode)
            if (afterChmod is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.close()
                return afterChmod
            }
            val labeled = directory.labelExactSocket(inode)
            if (labeled is BridgeResult.Failure) {
                runCatching { binding.close() }
                directory.deleteExactSocket(inode)
                directory.close()
                return labeled
            }
            val inspected = directory.inspectSocket()
            if (inspected !is BridgeResult.Success || inspected.value.inode != inode) {
                runCatching { binding.close() }
                directory.deleteExactSocket(inode)
                directory.close()
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
            return BridgeResult.Success(DonorBridgeServer(binding, directory, inode))
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
                val before = directory.inspectSocket()
                if (before is BridgeResult.Failure) {
                    directory.close()
                    throw BridgeTransportException(before.error)
                }
                val expectedInode = (before as BridgeResult.Success).value.inode
                val socket = LocalSocket()
                pending.set(socket)
                try {
                    socket.connect(
                        LocalSocketAddress(
                            directory.anchoredSocketPath.toString(),
                            LocalSocketAddress.Namespace.FILESYSTEM,
                        )
                    )
                    val after = directory.inspectSocket()
                    if (after !is BridgeResult.Success || after.value.inode != expectedInode) {
                        throw BridgeTransportException(BridgeError.SocketPathChanged)
                    }
                    AndroidLocalSocketTransport(socket)
                } catch (error: BridgeTransportException) {
                    runCatching { socket.close() }
                    throw error
                } catch (_: SecurityException) {
                    runCatching { socket.close() }
                    throw BridgeTransportException(BridgeError.SelinuxDenied)
                } catch (_: Exception) {
                    runCatching { socket.close() }
                    throw BridgeTransportException(BridgeError.SocketBindDenied)
                } finally {
                    directory.close()
                }
            },
            abortPending = { runCatching { pending.get()?.close() } },
        )
    }
}
