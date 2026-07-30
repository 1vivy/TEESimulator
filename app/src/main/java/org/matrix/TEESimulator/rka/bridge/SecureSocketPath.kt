package org.matrix.TEESimulator.rka.bridge

import android.system.Os
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

internal data class BridgePathIdentity(
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val isDirectory: Boolean,
    val isSocket: Boolean,
    val isSymlink: Boolean,
)

internal interface BridgeSocketPathOperations {
    fun createDirectories(path: Path)

    fun exists(path: Path): Boolean

    fun rejectSymlinkAncestors(path: Path)

    fun chown(path: Path, uid: Int, gid: Int)

    fun chmod(path: Path, mode: Int)

    fun restoreLabel(path: Path): Boolean

    fun stat(path: Path): BridgePathIdentity

    fun delete(path: Path)
}

internal object AndroidBridgeSocketPathOperations : BridgeSocketPathOperations {
    override fun createDirectories(path: Path) {
        Files.createDirectories(path)
    }

    override fun exists(path: Path): Boolean = Files.exists(path, LinkOption.NOFOLLOW_LINKS)

    override fun rejectSymlinkAncestors(path: Path) {
        var current: Path? = path.toAbsolutePath().root
        for (component in path.toAbsolutePath()) {
            current = requireNotNull(current).resolve(component)
            require(!Files.isSymbolicLink(current))
        }
    }

    override fun chown(path: Path, uid: Int, gid: Int) {
        Os.chown(path.toString(), uid, gid)
    }

    override fun chmod(path: Path, mode: Int) {
        Os.chmod(path.toString(), mode)
    }

    override fun restoreLabel(path: Path): Boolean =
        (Class.forName("android.os.SELinux")
            .getMethod("restorecon", File::class.java)
            .invoke(null, File(path.toString())) as? Boolean) == true

    override fun stat(path: Path): BridgePathIdentity {
        val attributes =
            Files.readAttributes(
                path,
                "unix:ino,uid,gid,mode,isDirectory,isSymbolicLink",
                LinkOption.NOFOLLOW_LINKS,
            )
        val mode = (attributes.getValue("mode") as Number).toInt()
        return BridgePathIdentity(
            inode = (attributes.getValue("ino") as Number).toLong(),
            uid = (attributes.getValue("uid") as Number).toInt(),
            gid = (attributes.getValue("gid") as Number).toInt(),
            mode = mode and 0x1ff,
            isDirectory = attributes.getValue("isDirectory") as Boolean,
            isSocket = mode and 0xf000 == 0xc000,
            isSymlink = attributes.getValue("isSymbolicLink") as Boolean,
        )
    }

    override fun delete(path: Path) {
        Files.deleteIfExists(path)
    }
}

internal data class SecureSocketDirectory(val path: Path, val inode: Long)

internal class SecureSocketPath(
    private val operations: BridgeSocketPathOperations = AndroidBridgeSocketPathOperations
) {
    fun prepare(
        socketPath: Path,
        requireAbsentSocket: Boolean = true,
    ): BridgeResult<SecureSocketDirectory> {
        val directory = socketPath.parent ?: return BridgeResult.Failure(BridgeError.SocketPolicy)
        try {
            operations.rejectSymlinkAncestors(directory)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
        try {
            operations.createDirectories(directory)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketCreateDenied)
        }
        try {
            operations.rejectSymlinkAncestors(directory)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
        if (requireAbsentSocket && operations.exists(socketPath)) {
            return BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
        try {
            operations.chown(directory, 0, 0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChownDenied)
        }
        try {
            operations.chmod(directory, 0x1c0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChmodDenied)
        }
        try {
            if (!operations.restoreLabel(directory)) {
                return BridgeResult.Failure(BridgeError.SocketLabelDenied)
            }
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        val identity =
            try {
                operations.stat(directory)
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        return if (
            identity.uid == 0 &&
                identity.gid == 0 &&
                identity.mode == 0x1c0 &&
                identity.isDirectory &&
                !identity.isSymlink
        ) {
            BridgeResult.Success(SecureSocketDirectory(directory, identity.inode))
        } else {
            BridgeResult.Failure(BridgeError.SocketPolicy)
        }
    }

    fun secureBoundSocket(directory: SecureSocketDirectory, socketPath: Path): BridgeResult<Long> {
        try {
            operations.chown(socketPath, 0, 0)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChownDenied)
        }
        try {
            operations.chmod(socketPath, 0x180)
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketChmodDenied)
        }
        try {
            if (!operations.restoreLabel(socketPath)) {
                return BridgeResult.Failure(BridgeError.SocketLabelDenied)
            }
        } catch (_: Exception) {
            return BridgeResult.Failure(BridgeError.SocketLabelDenied)
        }
        val currentDirectory =
            try {
                operations.stat(directory.path)
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        val socket =
            try {
                operations.stat(socketPath)
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.SocketPathChanged)
            }
        return if (
            currentDirectory.inode == directory.inode &&
                currentDirectory.uid == 0 &&
                currentDirectory.gid == 0 &&
                currentDirectory.mode == 0x1c0 &&
                currentDirectory.isDirectory &&
                !currentDirectory.isSymlink &&
                socket.uid == 0 &&
                socket.gid == 0 &&
                socket.mode == 0x180 &&
                socket.isSocket &&
                !socket.isSymlink
        ) {
            BridgeResult.Success(socket.inode)
        } else {
            BridgeResult.Failure(BridgeError.SocketPathChanged)
        }
    }

    fun deleteExact(socketPath: Path, inode: Long) {
        val current = runCatching { operations.stat(socketPath) }.getOrNull() ?: return
        if (current.inode == inode && current.isSocket && !current.isSymlink) {
            runCatching { operations.delete(socketPath) }
        }
    }

    fun cleanupNewSocket(socketPath: Path) {
        val current = runCatching { operations.stat(socketPath) }.getOrNull() ?: return
        if (current.isSocket && !current.isSymlink) deleteExact(socketPath, current.inode)
    }
}
