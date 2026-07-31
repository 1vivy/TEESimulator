package org.matrix.TEESimulator.rka.journal

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions

internal interface JournalSyncOps {
    fun validateTarget(path: Path)

    fun read(path: Path): ByteArray?

    fun createPrivateTemp(parent: Path): Path

    fun write(path: Path, value: ByteArray)

    fun fsyncFile(path: Path)

    fun atomicMove(source: Path, target: Path)

    fun fsyncDirectory(path: Path)

    fun deleteIfExists(path: Path)
}

class FileRkpJournalStore
internal constructor(private val path: Path, private val ops: JournalSyncOps = RootJournalSyncOps) :
    RkpJournalStore {
    override fun read(): ByteArray? = ops.read(path)?.also { require(it.size <= MAX_BYTES) }

    override fun replace(value: ByteArray) {
        require(value.size <= MAX_BYTES)
        ops.validateTarget(path)
        val parent = requireNotNull(path.parent)
        val temporary = ops.createPrivateTemp(parent)
        try {
            ops.write(temporary, value)
            ops.fsyncFile(temporary)
            ops.atomicMove(temporary, path)
            ops.fsyncDirectory(parent)
        } finally {
            ops.deleteIfExists(temporary)
        }
    }

    override fun clear() {
        ops.validateTarget(path)
        ops.deleteIfExists(path)
        ops.fsyncDirectory(requireNotNull(path.parent))
    }

    companion object {
        private const val MAX_BYTES = 131_072

        fun production(root: Path): FileRkpJournalStore =
            FileRkpJournalStore(root.resolve("rka/journal/rkp.journal"))
    }
}

private object RootJournalSyncOps : JournalSyncOps {
    private val fileMode =
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))

    override fun validateTarget(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        require(Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) == 0)
        require(Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rw-------"))
    }

    override fun read(path: Path): ByteArray? {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return null
        validateTarget(path)
        return Files.readAllBytes(path)
    }

    override fun createPrivateTemp(parent: Path): Path {
        require(Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS))
        require(Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) == 0)
        require(
            Files.getPosixFilePermissions(parent) == PosixFilePermissions.fromString("rwx------")
        )
        return Files.createTempFile(parent, ".rkp-journal-", ".tmp", fileMode)
    }

    override fun write(path: Path, value: ByteArray) {
        FileChannel.open(path, StandardOpenOption.WRITE).use { channel ->
            var buffer = ByteBuffer.wrap(value)
            while (buffer.hasRemaining()) channel.write(buffer)
        }
    }

    override fun fsyncFile(path: Path) {
        FileChannel.open(path, StandardOpenOption.WRITE).use { it.force(true) }
    }

    override fun atomicMove(source: Path, target: Path) {
        Files.move(
            source,
            target,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    override fun fsyncDirectory(path: Path) {
        FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
    }

    override fun deleteIfExists(path: Path) {
        Files.deleteIfExists(path)
    }
}
