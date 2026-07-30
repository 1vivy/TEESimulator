package org.matrix.TEESimulator.rka.bridge

import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.FileDescriptor
import java.nio.file.Path

internal data class BridgePathIdentity(
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val isDirectory: Boolean,
    val isSocket: Boolean,
    val context: String,
)

internal interface BridgeSocketDirectoryHandle : Closeable {
    val anchoredSocketPath: Path

    fun secureDirectory(): BridgeResult<Unit>

    fun inspectSocket(): BridgeResult<BridgePathIdentity>

    fun verifySocketInode(inode: Long): BridgeResult<Unit>

    fun labelExactSocket(inode: Long): BridgeResult<Unit>

    fun deleteExactSocket(inode: Long)
}

internal fun interface BridgeSocketPathOperations {
    fun openFixedDirectory(socketPath: Path): BridgeResult<BridgeSocketDirectoryHandle>
}

internal object AndroidBridgeSocketPathOperations : BridgeSocketPathOperations {
    override fun openFixedDirectory(socketPath: Path): BridgeResult<BridgeSocketDirectoryHandle> {
        if (socketPath != SecureSocketPath.FIXED_SOCKET_PATH) {
            return BridgeResult.Failure(BridgeError.SocketPolicy)
        }
        val parentDescriptor =
            try {
                Os.open(
                    socketPath.parent.parent.toString(),
                    OsConstants.O_RDONLY or
                        O_DIRECTORY or
                        OsConstants.O_NOFOLLOW or
                        OsConstants.O_CLOEXEC,
                    0,
                )
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.SocketCreateDenied)
            }
        try {
            if (!isSecureDirectory(Os.fstat(parentDescriptor))) {
                return BridgeResult.Failure(BridgeError.SocketPolicy)
            }
            val parentAnchor = descriptorPath(parentDescriptor)
            val directoryPath = Path.of(parentAnchor, socketPath.parent.fileName.toString())
            try {
                Os.mkdir(directoryPath.toString(), DIRECTORY_MODE)
            } catch (error: android.system.ErrnoException) {
                if (error.errno != OsConstants.EEXIST) {
                    return BridgeResult.Failure(BridgeError.SocketCreateDenied)
                }
            }
            val descriptor =
                try {
                    Os.open(
                        directoryPath.toString(),
                        OsConstants.O_RDONLY or
                            O_DIRECTORY or
                            OsConstants.O_NOFOLLOW or
                            OsConstants.O_CLOEXEC,
                        0,
                    )
                } catch (_: Exception) {
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
            return try {
                BridgeResult.Success(
                    AndroidBridgeSocketDirectoryHandle(descriptor, socketPath.fileName.toString())
                )
            } catch (_: Exception) {
                runCatching { Os.close(descriptor) }
                BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        } finally {
            runCatching { Os.close(parentDescriptor) }
        }
    }

    private fun isSecureDirectory(stat: android.system.StructStat): Boolean =
        stat.st_uid == 0 &&
            stat.st_gid == 0 &&
            stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR &&
            stat.st_mode and 0x1ff == DIRECTORY_MODE

    private fun descriptorPath(descriptor: FileDescriptor): String =
        "/proc/self/fd/${descriptorNumber(descriptor)}"

    private fun descriptorNumber(descriptor: FileDescriptor): Int =
        FileDescriptor::class.java.getDeclaredMethod("getInt$").invoke(descriptor) as Int

    private const val DIRECTORY_MODE = 0x1c0
    private const val O_DIRECTORY = 0x10000
}

private class AndroidBridgeSocketDirectoryHandle(
    private val descriptor: FileDescriptor,
    socketName: String,
) : BridgeSocketDirectoryHandle {
    private val directoryAnchor = Path.of("/proc/self/fd/${descriptorNumber(descriptor)}")
    override val anchoredSocketPath: Path = directoryAnchor.resolve(socketName)
    private val originalDirectoryInode = Os.fstat(descriptor).st_ino

    override fun secureDirectory(): BridgeResult<Unit> {
        try {
            Os.fchown(descriptor, 0, 0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChownDenied)
        }
        try {
            Os.fchmod(descriptor, DIRECTORY_MODE)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChmodDenied)
        }
        if (!setAndVerifyContext(directoryAnchor, DIRECTORY_CONTEXT)) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        val stat =
            runCatching { Os.fstat(descriptor) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
        return if (
            stat.st_ino == originalDirectoryInode &&
                stat.st_uid == 0 &&
                stat.st_gid == 0 &&
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR &&
                stat.st_mode and 0x1ff == DIRECTORY_MODE
        ) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    override fun inspectSocket(): BridgeResult<BridgePathIdentity> {
        if (!directoryUnchanged()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        val stat =
            runCatching { Os.lstat(anchoredSocketPath.toString()) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
        val context =
            fileContext(anchoredSocketPath)
                ?: return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        if (context != SOCKET_CONTEXT) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        return if (
            stat.st_uid == 0 &&
                stat.st_gid == 0 &&
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK &&
                stat.st_mode and 0x1ff == SOCKET_MODE
        ) {
            BridgeResult.Success(
                BridgePathIdentity(
                    stat.st_ino,
                    stat.st_uid,
                    stat.st_gid,
                    stat.st_mode and 0x1ff,
                    isDirectory = false,
                    isSocket = true,
                    context = context,
                )
            )
        } else {
            BridgeResult.Failure(BridgeError.SocketPolicy)
        }
    }

    override fun labelExactSocket(inode: Long): BridgeResult<Unit> {
        if (!socketIsExact(inode)) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        if (!setAndVerifyContext(anchoredSocketPath, SOCKET_CONTEXT)) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        return if (socketIsExact(inode)) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    override fun verifySocketInode(inode: Long): BridgeResult<Unit> =
        if (socketIsExact(inode)) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }

    override fun deleteExactSocket(inode: Long) {
        if (!socketIsExact(inode)) return
        runCatching { Os.remove(anchoredSocketPath.toString()) }
    }

    override fun close() {
        runCatching { Os.close(descriptor) }
    }

    private fun directoryUnchanged(): Boolean =
        runCatching {
                val stat = Os.fstat(descriptor)
                stat.st_ino == originalDirectoryInode &&
                    stat.st_uid == 0 &&
                    stat.st_gid == 0 &&
                    stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR &&
                    stat.st_mode and 0x1ff == DIRECTORY_MODE &&
                    fileContext(directoryAnchor) == DIRECTORY_CONTEXT
            }
            .getOrDefault(false)

    private fun socketIsExact(inode: Long): Boolean =
        directoryUnchanged() &&
            runCatching {
                    val stat = Os.lstat(anchoredSocketPath.toString())
                    stat.st_ino == inode &&
                        stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK
                }
                .getOrDefault(false)

    private fun setAndVerifyContext(path: Path, context: String): Boolean =
        runCatching {
                val selinux = Class.forName("android.os.SELinux")
                val set =
                    selinux.getMethod("setFileContext", String::class.java, String::class.java)
                set.invoke(null, path.toString(), context) == true && fileContext(path) == context
            }
            .getOrDefault(false)

    private fun fileContext(path: Path): String? =
        runCatching {
                Class.forName("android.os.SELinux")
                    .getMethod("getFileContext", String::class.java)
                    .invoke(null, path.toString()) as? String
            }
            .getOrNull()

    private fun descriptorNumber(value: FileDescriptor): Int =
        FileDescriptor::class.java.getDeclaredMethod("getInt$").invoke(value) as Int

    private companion object {
        const val DIRECTORY_MODE = 0x1c0
        const val SOCKET_MODE = 0x180
        const val DIRECTORY_CONTEXT = "u:object_r:teesimulator_rka_socket_dir:s0"
        const val SOCKET_CONTEXT = "u:object_r:teesimulator_rka_socket:s0"
    }
}

internal class SecureSocketPath(
    private val operations: BridgeSocketPathOperations = AndroidBridgeSocketPathOperations
) {
    fun open(): BridgeResult<BridgeSocketDirectoryHandle> =
        when (val opened = operations.openFixedDirectory(FIXED_SOCKET_PATH)) {
            is BridgeResult.Failure -> opened
            is BridgeResult.Success ->
                when (val secured = opened.value.secureDirectory()) {
                    is BridgeResult.Failure -> {
                        opened.value.close()
                        secured
                    }
                    is BridgeResult.Success -> opened
                }
        }

    internal fun open(socketPath: Path): BridgeResult<BridgeSocketDirectoryHandle> =
        when (val opened = operations.openFixedDirectory(socketPath)) {
            is BridgeResult.Failure -> opened
            is BridgeResult.Success ->
                when (val secured = opened.value.secureDirectory()) {
                    is BridgeResult.Failure -> {
                        opened.value.close()
                        secured
                    }
                    is BridgeResult.Success -> opened
                }
        }

    internal companion object {
        val FIXED_SOCKET_PATH: Path = Path.of("/data/adb/teesimulator-rka/run/sockets/broker.sock")
    }
}
