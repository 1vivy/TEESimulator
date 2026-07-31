package org.matrix.teesimulator.rkahost.cli

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission

object BaselineStore {
    private val fileMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun create(path: Path, baseline: SentinelBaseline) {
        writeExclusive(path, baseline)
    }

    fun requireReadyAbsent(path: Path) {
        if (Files.isSymbolicLink(path)) throw HostCliException("BASELINE_PATH_UNSAFE")
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("BASELINE_ALREADY_EXISTS")
        }
        safeParent(path)
    }

    fun createPending(path: Path, baseline: SentinelBaseline) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("BASELINE_ALREADY_EXISTS")
        }
        writeExclusive(pending(path), baseline)
    }

    fun commitPending(path: Path, baseline: SentinelBaseline) {
        if (readPending(path) != baseline) throw HostCliException("BASELINE_PENDING_INVALID")
        try {
            Files.createLink(path, pending(path))
        } catch (_: java.nio.file.FileAlreadyExistsException) {
            throw HostCliException("BASELINE_ALREADY_EXISTS")
        }
        Files.delete(pending(path))
        fsyncParent(path)
    }

    fun abortPending(path: Path) {
        Files.deleteIfExists(pending(path))
        fsyncParent(path)
    }

    fun hasPending(path: Path): Boolean = Files.exists(pending(path), LinkOption.NOFOLLOW_LINKS)

    fun finalizeCommittedPending(path: Path): Boolean {
        if (!hasPending(path) || Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) return false
        if (read(path) != readPending(path)) throw HostCliException("BASELINE_PENDING_INVALID")
        abortPending(path)
        return true
    }

    fun readPending(path: Path): SentinelBaseline = readPrivate(pending(path))

    fun read(path: Path): SentinelBaseline = readPrivate(path)

    private fun writeExclusive(path: Path, baseline: SentinelBaseline) {
        val parent = safeParent(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw HostCliException(
                if (Files.isSymbolicLink(path)) "BASELINE_PATH_UNSAFE"
                else "BASELINE_ALREADY_EXISTS"
            )
        }
        val temporary = Files.createTempFile(parent, ".baseline-", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, fileMode)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(baseline.canonical().toByteArray()))
                it.force(true)
            }
            try {
                Files.createLink(path, temporary)
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                throw HostCliException("BASELINE_ALREADY_EXISTS")
            }
            fsyncParent(path)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun readPrivate(path: Path): SentinelBaseline {
        if (
            Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.getPosixFilePermissions(path) != fileMode
        ) {
            throw HostCliException("BASELINE_PATH_UNSAFE")
        }
        return SentinelBaseline.parse(Files.readString(path))
    }

    private fun safeParent(path: Path): Path {
        val parent = path.toAbsolutePath().parent ?: throw HostCliException("BASELINE_PATH_UNSAFE")
        if (Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("BASELINE_PATH_UNSAFE")
        }
        return parent
    }

    private fun pending(path: Path): Path = path.resolveSibling(".${path.fileName}.pending")

    private fun fsyncParent(path: Path) {
        FileChannel.open(safeParent(path), StandardOpenOption.READ).use { it.force(true) }
    }
}
