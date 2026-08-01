package org.matrix.teesimulator.rkahost.cli

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission

object BaselineStore {
    private val fileMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val creationLock = Any()

    fun create(path: Path, baseline: SentinelBaseline) {
        synchronized(creationLock) { writeExclusive(path, baseline) }
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
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("BASELINE_ALREADY_EXISTS")
        }
        TraceIo.atomicMove(pending(path), path, false)
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

    fun delete(path: Path, baseline: SentinelBaseline) {
        if (read(path) != baseline) throw HostCliException("BASELINE_INVALID")
        Files.delete(path)
        fsyncParent(path)
    }

    private fun writeExclusive(path: Path, baseline: SentinelBaseline) {
        safeParent(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw HostCliException(
                if (Files.isSymbolicLink(path)) "BASELINE_PATH_UNSAFE"
                else "BASELINE_ALREADY_EXISTS"
            )
        }
        try {
            TraceIo.atomicWrite(path, baseline.canonical().toByteArray(), false)
        } catch (failure: HostCliException) {
            if (failure.message == "COMMAND_TRACE_EXISTS") {
                throw HostCliException("BASELINE_ALREADY_EXISTS")
            }
            throw failure
        }
    }

    private fun readPrivate(path: Path): SentinelBaseline {
        TraceIo.requirePrivate(path, "BASELINE_PATH_UNSAFE")
        return SentinelBaseline.parse(Files.readString(path))
    }

    private fun safeParent(path: Path): Path {
        return try {
            TraceIo.requireOwnedDirectory(path)
        } catch (_: HostCliException) {
            throw HostCliException("BASELINE_PATH_UNSAFE")
        }
    }

    private fun pending(path: Path): Path = path.resolveSibling(".${path.fileName}.pending")

    private fun fsyncParent(path: Path) {
        FileChannel.open(safeParent(path), StandardOpenOption.READ).use { it.force(true) }
    }
}
