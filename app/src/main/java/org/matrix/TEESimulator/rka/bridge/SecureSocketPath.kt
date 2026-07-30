package org.matrix.TEESimulator.rka.bridge

import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.Closeable
import java.io.FileDescriptor
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.security.SecureRandom

internal data class BridgePathIdentity(
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val isDirectory: Boolean,
    val isSocket: Boolean,
    val context: String,
)

internal interface BridgeSocketNodeHandle : Closeable {
    val inode: Long

    fun chownRoot(): BridgeResult<Unit>

    fun chmodOwnerOnly(): BridgeResult<Unit>

    fun verifyDedicatedContext(): BridgeResult<Unit>

    fun inspect(): BridgeResult<BridgePathIdentity>

    fun verifyStillNamed(): BridgeResult<Unit>

    fun deleteIfStillNamed()
}

internal interface BridgeSocketDirectoryHandle : Closeable {
    val anchoredSocketPath: Path

    fun secureDirectory(): BridgeResult<Unit>

    fun openSocketNode(): BridgeResult<BridgeSocketNodeHandle>
}

internal fun interface BridgeSocketPathOperations {
    fun openFixedDirectory(socketPath: Path): BridgeResult<BridgeSocketDirectoryHandle>
}

internal object AndroidBridgeSocketPathOperations : BridgeSocketPathOperations {
    override fun openFixedDirectory(socketPath: Path): BridgeResult<BridgeSocketDirectoryHandle> {
        if (socketPath != SecureSocketPath.FIXED_SOCKET_PATH) {
            return BridgeResult.Failure(BridgeError.SocketPolicy)
        }
        val held = mutableListOf<HeldSocketDirectory>()
        var secureStream: SecureDirectoryStream<Path>? = null
        try {
            val root = openDirectoryComponent(null, "")
            held += HeldSocketDirectory("", root, SocketDirectorySignature.from(Os.fstat(root)))
            for (name in PARENT_COMPONENTS) {
                val descriptor = openDirectoryComponent(held.last().descriptor, name)
                val signature = SocketDirectorySignature.from(Os.fstat(descriptor))
                if (!signature.directory) {
                    Os.close(descriptor)
                    return closeAndFail(held, BridgeError.SocketPolicy)
                }
                held += HeldSocketDirectory(name, descriptor, signature)
            }
            if (!protectedDirectoriesAreValid(held)) {
                return closeAndFail(held, BridgeError.SocketPolicy)
            }
            val run = held.last()
            val socketsPath = "${descriptorPath(run.descriptor)}/$SOCKET_DIRECTORY_NAME"
            try {
                Os.mkdir(socketsPath, DIRECTORY_MODE)
            } catch (error: android.system.ErrnoException) {
                if (error.errno != OsConstants.EEXIST) {
                    return closeAndFail(held, BridgeError.SocketCreateDenied)
                }
            }
            val socketsDescriptor = openDirectoryComponent(run.descriptor, SOCKET_DIRECTORY_NAME)
            val socketsSignature = SocketDirectorySignature.from(Os.fstat(socketsDescriptor))
            held += HeldSocketDirectory(SOCKET_DIRECTORY_NAME, socketsDescriptor, socketsSignature)
            val openedStream = Files.newDirectoryStream(Path.of(descriptorPath(socketsDescriptor)))
            if (openedStream !is SecureDirectoryStream<Path>) {
                openedStream.close()
                return closeAndFail(held, BridgeError.SocketPolicy)
            }
            secureStream = openedStream
            return BridgeResult.Success(
                AndroidBridgeSocketDirectoryHandle(
                    held.toList(),
                    secureStream,
                    socketPath.fileName.toString(),
                )
            )
        } catch (_: SecurityException) {
            secureStream?.let { runCatching { it.close() } }
            closeHeld(held)
            return BridgeResult.Failure(BridgeError.SelinuxDenied)
        } catch (_: Exception) {
            secureStream?.let { runCatching { it.close() } }
            closeHeld(held)
            return BridgeResult.Failure(BridgeError.SocketCreateDenied)
        }
    }

    private fun openDirectoryComponent(parent: FileDescriptor?, name: String): FileDescriptor {
        val path = if (parent == null) "/" else "${descriptorPath(parent)}/$name"
        return Os.open(
            path,
            OsConstants.O_RDONLY or O_DIRECTORY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
            0,
        )
    }

    private fun protectedDirectoriesAreValid(held: List<HeldSocketDirectory>): Boolean =
        held
            .filter { it.name in PROTECTED_COMPONENTS }
            .all {
                it.signature.directory &&
                    it.signature.uid == 0 &&
                    it.signature.gid == 0 &&
                    it.signature.mode == DIRECTORY_MODE
            }

    private fun closeAndFail(
        held: List<HeldSocketDirectory>,
        error: BridgeError,
    ): BridgeResult.Failure {
        closeHeld(held)
        return BridgeResult.Failure(error)
    }

    private fun closeHeld(held: List<HeldSocketDirectory>) {
        held.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
    }

    private val PARENT_COMPONENTS = listOf("data", "adb", "teesimulator-rka", "run")
    private val PROTECTED_COMPONENTS = setOf("teesimulator-rka", "run")
    private const val SOCKET_DIRECTORY_NAME = "sockets"
    private const val DIRECTORY_MODE = 0x1c0
    private const val O_DIRECTORY = 0x10000
}

private class AndroidBridgeSocketDirectoryHandle(
    private val directories: List<HeldSocketDirectory>,
    private val secureStream: SecureDirectoryStream<Path>,
    private val socketName: String,
) : BridgeSocketDirectoryHandle {
    private val directory = directories.last()
    private val directoryAnchor = Path.of(descriptorPath(directory.descriptor))
    override val anchoredSocketPath: Path = directoryAnchor.resolve(socketName)

    override fun secureDirectory(): BridgeResult<Unit> {
        if (!chainStillNamed()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        try {
            Os.fchown(directory.descriptor, 0, 0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChownDenied)
        }
        try {
            Os.fchmod(directory.descriptor, DIRECTORY_MODE)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChmodDenied)
        }
        val stat =
            runCatching { Os.fstat(directory.descriptor) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
        if (
            !chainStillNamed() ||
                stat.st_ino != directory.signature.inode ||
                stat.st_dev != directory.signature.device ||
                stat.st_uid != 0 ||
                stat.st_gid != 0 ||
                stat.st_mode and OsConstants.S_IFMT != OsConstants.S_IFDIR ||
                stat.st_mode and 0x1ff != DIRECTORY_MODE
        ) {
            return BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
        return if (fileContext(directoryAnchor) == DIRECTORY_CONTEXT) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
    }

    override fun openSocketNode(): BridgeResult<BridgeSocketNodeHandle> {
        if (!chainStillNamed()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        val descriptor =
            try {
                Os.open(
                    anchoredSocketPath.toString(),
                    O_PATH or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                    0,
                )
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        val stat =
            try {
                Os.fstat(descriptor)
            } catch (_: Exception) {
                runCatching { Os.close(descriptor) }
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        if (stat.st_mode and OsConstants.S_IFMT != OsConstants.S_IFSOCK) {
            runCatching { Os.close(descriptor) }
            return BridgeResult.Failure(BridgeError.SocketPolicy)
        }
        val handle =
            AndroidBridgeSocketNodeHandle(
                descriptor,
                stat.st_dev,
                stat.st_ino,
                this,
                secureStream,
                socketName,
            )
        return if (handle.verifyStillNamed() is BridgeResult.Success) {
            BridgeResult.Success(handle)
        } else {
            handle.close()
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    internal fun chainStillNamed(): Boolean {
        for (directory in directories) {
            val held =
                runCatching { SocketDirectorySignature.from(Os.fstat(directory.descriptor)) }
                    .getOrElse {
                        return false
                    }
            if (
                held.device != directory.signature.device ||
                    held.inode != directory.signature.inode ||
                    !held.directory
            ) {
                return false
            }
        }
        for (index in 1 until directories.size) {
            val parent = directories[index - 1]
            val child = directories[index]
            val named =
                runCatching {
                        SocketDirectorySignature.from(
                            Os.lstat("${descriptorPath(parent.descriptor)}/${child.name}")
                        )
                    }
                    .getOrElse {
                        return false
                    }
            if (
                named.device != child.signature.device ||
                    named.inode != child.signature.inode ||
                    !named.directory
            ) {
                return false
            }
        }
        return true
    }

    override fun close() {
        runCatching { secureStream.close() }
        directories.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
    }

    private companion object {
        const val DIRECTORY_MODE = 0x1c0
        const val DIRECTORY_CONTEXT = "u:object_r:teesimulator_rka_socket_dir:s0"
        const val O_PATH = 0x200000
    }
}

private class AndroidBridgeSocketNodeHandle(
    private val descriptor: FileDescriptor,
    private val device: Long,
    override val inode: Long,
    private val directory: AndroidBridgeSocketDirectoryHandle,
    private val secureStream: SecureDirectoryStream<Path>,
    private val socketName: String,
) : BridgeSocketNodeHandle {
    private val nodeAnchor = Path.of(descriptorPath(descriptor))

    override fun chownRoot(): BridgeResult<Unit> {
        if (!heldNodeUnchanged()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        try {
            Os.chown(nodeAnchor.toString(), 0, 0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChownDenied)
        }
        val after = inspectStat() ?: return BridgeResult.Failure(BridgeError.SocketPathChanged)
        return if (after.st_uid == 0 && after.st_gid == 0) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    override fun chmodOwnerOnly(): BridgeResult<Unit> {
        if (!heldNodeUnchanged()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        try {
            Os.chmod(nodeAnchor.toString(), SOCKET_MODE)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChmodDenied)
        }
        val after = inspectStat() ?: return BridgeResult.Failure(BridgeError.SocketPathChanged)
        return if (after.st_mode and 0x1ff == SOCKET_MODE) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    override fun verifyDedicatedContext(): BridgeResult<Unit> {
        if (!heldNodeUnchanged()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        if (fileContext(nodeAnchor) != SOCKET_CONTEXT) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        return if (heldNodeUnchanged()) BridgeResult.Success(Unit)
        else BridgeResult.Failure(BridgeError.SocketPathChanged)
    }

    override fun inspect(): BridgeResult<BridgePathIdentity> {
        if (!heldNodeUnchanged()) return BridgeResult.Failure(BridgeError.SocketPathChanged)
        val stat = inspectStat() ?: return BridgeResult.Failure(BridgeError.SocketPathChanged)
        val context =
            fileContext(nodeAnchor) ?: return BridgeResult.Failure(BridgeError.SocketLabelDenied)
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

    override fun verifyStillNamed(): BridgeResult<Unit> =
        if (heldNodeUnchanged() && namedEntryMatches()) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }

    override fun deleteIfStillNamed() {
        if (verifyStillNamed() is BridgeResult.Failure) return
        val quarantine = ".broker.sock.delete-${randomToken()}"
        try {
            secureStream.move(Path.of(socketName), secureStream, Path.of(quarantine))
        } catch (_: Exception) {
            return
        }
        val movedPath = Path.of(descriptorPathForDirectory(), quarantine)
        val moved =
            runCatching { Os.lstat(movedPath.toString()) }
                .getOrElse {
                    return
                }
        if (
            moved.st_dev != device ||
                moved.st_ino != inode ||
                moved.st_mode and OsConstants.S_IFMT != OsConstants.S_IFSOCK
        ) {
            runCatching {
                secureStream.move(Path.of(quarantine), secureStream, Path.of(socketName))
            }
            return
        }
        runCatching { secureStream.deleteFile(Path.of(quarantine)) }
    }

    private fun heldNodeUnchanged(): Boolean {
        if (!directory.chainStillNamed()) return false
        val stat = inspectStat() ?: return false
        return stat.st_dev == device &&
            stat.st_ino == inode &&
            stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK
    }

    private fun namedEntryMatches(): Boolean {
        val stat =
            runCatching { Os.lstat(Path.of(descriptorPathForDirectory(), socketName).toString()) }
                .getOrElse {
                    return false
                }
        return stat.st_dev == device &&
            stat.st_ino == inode &&
            stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFSOCK
    }

    private fun inspectStat(): StructStat? = runCatching { Os.fstat(descriptor) }.getOrNull()

    private fun descriptorPathForDirectory(): String =
        directory.anchoredSocketPath.parent.toString()

    override fun close() {
        runCatching { Os.close(descriptor) }
    }

    private fun randomToken(): String =
        ByteArray(16).also(SecureRandom()::nextBytes).joinToString(separator = "") {
            "%02x".format(it)
        }

    private companion object {
        const val SOCKET_MODE = 0x180
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

private data class HeldSocketDirectory(
    val name: String,
    val descriptor: FileDescriptor,
    val signature: SocketDirectorySignature,
)

private data class SocketDirectorySignature(
    val device: Long,
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val directory: Boolean,
) {
    companion object {
        fun from(stat: StructStat): SocketDirectorySignature =
            SocketDirectorySignature(
                stat.st_dev,
                stat.st_ino,
                stat.st_uid,
                stat.st_gid,
                stat.st_mode and 0x1ff,
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR,
            )
    }
}

private fun fileContext(path: Path): String? =
    runCatching {
            Class.forName("android.os.SELinux")
                .getMethod("getFileContext", String::class.java)
                .invoke(null, path.toString()) as? String
        }
        .getOrNull()

private fun descriptorPath(descriptor: FileDescriptor): String =
    "/proc/self/fd/${descriptorNumber(descriptor)}"

private fun descriptorNumber(descriptor: FileDescriptor): Int =
    FileDescriptor::class.java.getDeclaredMethod("getInt$").invoke(descriptor) as Int
