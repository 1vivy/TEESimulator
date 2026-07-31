package org.matrix.teesimulator.rkahost.cli

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission

internal enum class EvidenceCommitPoint {
    CBOR_STAGING,
    CBOR_STAGED,
    MARKER_PUBLISHED,
    JSON_PUBLISHED,
    CBOR_PUBLISHED,
}

object EvidenceStore {
    private val fileMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun write(jsonPath: Path, receipt: String) {
        write(jsonPath, receipt) {}
    }

    internal fun write(jsonPath: Path, receipt: String, inject: (EvidenceCommitPoint) -> Unit) {
        val paths = EvidencePaths.from(jsonPath)
        withLock(paths) { writeLocked(paths, receipt, inject) }
    }

    private fun writeLocked(
        paths: EvidencePaths,
        receipt: String,
        inject: (EvidenceCommitPoint) -> Unit,
    ) {
        recover(paths)
        val hadOld = preflight(paths)
        val jsonBytes = receipt.toByteArray()
        val cborBytes = EvidenceCbor.encode(receipt)
        val jsonTemp = stage(paths.parent, "json", jsonBytes)
        var cborTemp: Path? = null
        try {
            inject(EvidenceCommitPoint.CBOR_STAGING)
            val stagedCbor = stage(paths.parent, "cbor", cborBytes)
            cborTemp = stagedCbor
            if (Files.readAllBytes(jsonTemp).contentEquals(jsonBytes).not()) {
                throw HostCliException("EVIDENCE_STAGE_INVALID")
            }
            if (EvidenceCbor.decode(Files.readAllBytes(stagedCbor)) != receipt) {
                throw HostCliException("EVIDENCE_STAGE_INVALID")
            }
            inject(EvidenceCommitPoint.CBOR_STAGED)
            if (hadOld) {
                Files.createLink(paths.jsonBackup, paths.json)
                Files.createLink(paths.cborBackup, paths.cbor)
            }
            writeExclusive(paths.marker, if (hadOld) "OLD\n" else "NONE\n")
            inject(EvidenceCommitPoint.MARKER_PUBLISHED)
            Files.move(
                jsonTemp,
                paths.json,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            inject(EvidenceCommitPoint.JSON_PUBLISHED)
            Files.move(
                stagedCbor,
                paths.cbor,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            inject(EvidenceCommitPoint.CBOR_PUBLISHED)
            fsync(paths.parent)
            Files.delete(paths.marker)
            fsync(paths.parent)
            Files.deleteIfExists(paths.jsonBackup)
            Files.deleteIfExists(paths.cborBackup)
        } catch (failure: Exception) {
            recover(paths)
            if (failure is HostCliException) throw failure
            throw HostCliException("EVIDENCE_WRITE_FAILED")
        } finally {
            Files.deleteIfExists(jsonTemp)
            cborTemp?.let(Files::deleteIfExists)
        }
    }

    fun read(jsonPath: Path): String {
        val paths = EvidencePaths.from(jsonPath)
        return withLock(paths) {
            recover(paths)
            if (!preflight(paths)) throw HostCliException("EVIDENCE_MISSING")
            val json = Files.readString(paths.json)
            if (EvidenceCbor.decode(Files.readAllBytes(paths.cbor)) != json) {
                throw HostCliException("EVIDENCE_PAIR_MISMATCH")
            }
            json
        }
    }

    private fun <T> withLock(paths: EvidencePaths, operation: () -> T): T {
        if (Files.notExists(paths.lock, LinkOption.NOFOLLOW_LINKS)) {
            val temporary = stage(paths.parent, "lock", byteArrayOf())
            try {
                try {
                    Files.createLink(paths.lock, temporary)
                } catch (_: java.nio.file.FileAlreadyExistsException) {
                    Unit
                }
            } finally {
                Files.deleteIfExists(temporary)
            }
        }
        validatePrivate(paths.lock)
        val options: Set<OpenOption> =
            setOf(StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
        return FileChannel.open(paths.lock, options).use { channel ->
            channel.lock().use { operation() }
        }
    }

    private fun recover(paths: EvidencePaths) {
        validateInternal(paths.marker)
        if (Files.notExists(paths.marker, LinkOption.NOFOLLOW_LINKS)) {
            deleteInternal(paths.jsonBackup)
            deleteInternal(paths.cborBackup)
            return
        }
        val state = Files.readString(paths.marker)
        when (state) {
            "OLD\n" -> {
                validatePrivate(paths.jsonBackup)
                validatePrivate(paths.cborBackup)
                restore(paths.jsonBackup, paths.json)
                restore(paths.cborBackup, paths.cbor)
            }
            "NONE\n" -> {
                deletePublished(paths.json)
                deletePublished(paths.cbor)
            }
            else -> throw HostCliException("EVIDENCE_TRANSACTION_INVALID")
        }
        fsync(paths.parent)
        Files.delete(paths.marker)
        fsync(paths.parent)
        deleteInternal(paths.jsonBackup)
        deleteInternal(paths.cborBackup)
    }

    private fun preflight(paths: EvidencePaths): Boolean {
        if (
            Files.isSymbolicLink(paths.parent) ||
                !Files.isDirectory(paths.parent, LinkOption.NOFOLLOW_LINKS)
        ) {
            throw HostCliException("EVIDENCE_PATH_UNSAFE")
        }
        FileChannel.open(paths.parent, StandardOpenOption.READ).use {}
        val jsonExists = Files.exists(paths.json, LinkOption.NOFOLLOW_LINKS)
        val cborExists = Files.exists(paths.cbor, LinkOption.NOFOLLOW_LINKS)
        if (jsonExists != cborExists) throw HostCliException("EVIDENCE_PAIR_INCOMPLETE")
        if (jsonExists) {
            validatePrivate(paths.json)
            validatePrivate(paths.cbor)
        } else if (Files.isSymbolicLink(paths.json) || Files.isSymbolicLink(paths.cbor)) {
            throw HostCliException("EVIDENCE_PATH_UNSAFE")
        }
        return jsonExists
    }

    private fun stage(parent: Path, label: String, bytes: ByteArray): Path {
        val path = Files.createTempFile(parent, ".evidence-$label-", ".tmp")
        Files.setPosixFilePermissions(path, fileMode)
        FileChannel.open(path, StandardOpenOption.WRITE).use {
            it.write(ByteBuffer.wrap(bytes))
            it.force(true)
        }
        return path
    }

    private fun writeExclusive(path: Path, value: String) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("EVIDENCE_TRANSACTION_BUSY")
        }
        val temporary = stage(path.parent, "marker", value.toByteArray())
        try {
            Files.createLink(path, temporary)
            fsync(path.parent)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun validatePrivate(path: Path) {
        if (
            Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.getPosixFilePermissions(path) != fileMode
        ) {
            throw HostCliException("EVIDENCE_PATH_UNSAFE")
        }
        val options: Set<OpenOption> = setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
        Files.newByteChannel(path, options).use {}
    }

    private fun validateInternal(path: Path) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) validatePrivate(path)
        else if (Files.isSymbolicLink(path)) throw HostCliException("EVIDENCE_PATH_UNSAFE")
    }

    private fun restore(backup: Path, target: Path) {
        deletePublished(target)
        val restore = backup.resolveSibling(".${backup.fileName}.restore")
        Files.deleteIfExists(restore)
        Files.createLink(restore, backup)
        Files.move(restore, target, StandardCopyOption.ATOMIC_MOVE)
    }

    private fun deletePublished(path: Path) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("EVIDENCE_PATH_UNSAFE")
        }
        Files.delete(path)
    }

    private fun deleteInternal(path: Path) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) return
        validatePrivate(path)
        Files.delete(path)
    }

    private fun fsync(parent: Path) {
        FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
    }
}
