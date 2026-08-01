package org.matrix.teesimulator.rkahost.cli

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.UUID

data class DeploySurfaceBinding(
    val entrypointSha256: String,
    val entrypointPathSha256: String,
    val surfaceSha256: String,
) {
    init {
        if (
            listOf(entrypointSha256, entrypointPathSha256, surfaceSha256).any { !it.matches(SHA) }
        ) {
            throw HostCliException("DEPLOY_SOURCE_BINDING_INVALID")
        }
    }

    companion object {
        private val SHA = Regex("[0-9a-f]{64}")
        val TEST = DeploySurfaceBinding("0".repeat(64), "1".repeat(64), "2".repeat(64))

        fun fromEnvironment(): DeploySurfaceBinding =
            DeploySurfaceBinding(
                required("RKA_TRACE_DEPLOY_SHA256"),
                required("RKA_TRACE_DEPLOY_PATH_SHA256"),
                required("RKA_TRACE_SURFACE_SHA256"),
            )

        private fun required(name: String): String =
            System.getenv(name)?.takeIf { it.matches(SHA) }
                ?: throw HostCliException("DEPLOY_SOURCE_BINDING_MISSING")
    }
}

internal enum class TraceIoPoint {
    BEFORE_FILE_FSYNC,
    BEFORE_ATOMIC_MOVE,
    BEFORE_PARENT_FSYNC,
}

internal object TraceIo {
    val privateMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    @Volatile internal var faultForTests: ((TraceIoPoint) -> Unit)? = null
    @Volatile internal var ownerForTests: ((Path) -> String)? = null

    fun atomicWrite(path: Path, bytes: ByteArray, replace: Boolean) {
        val parent = requireOwnedDirectory(path)
        val temporary = Files.createTempFile(parent, ".${path.fileName}.", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, privateMode)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use { channel ->
                channel.write(ByteBuffer.wrap(bytes))
                faultForTests?.invoke(TraceIoPoint.BEFORE_FILE_FSYNC)
                channel.force(true)
            }
            faultForTests?.invoke(TraceIoPoint.BEFORE_ATOMIC_MOVE)
            val options =
                if (replace) {
                    arrayOf(StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                } else {
                    arrayOf(StandardCopyOption.ATOMIC_MOVE)
                }
            Files.move(temporary, path, *options)
            faultForTests?.invoke(TraceIoPoint.BEFORE_PARENT_FSYNC)
            fsyncDirectory(parent)
        } catch (_: java.nio.file.FileAlreadyExistsException) {
            throw HostCliException("COMMAND_TRACE_EXISTS")
        } catch (failure: HostCliException) {
            throw failure
        } catch (_: Exception) {
            throw HostCliException("COMMAND_TRACE_PERSIST_FAILED")
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun atomicMove(source: Path, target: Path, replace: Boolean) {
        val parent = requireOwnedDirectory(target)
        requirePrivate(source)
        try {
            faultForTests?.invoke(TraceIoPoint.BEFORE_ATOMIC_MOVE)
            val options =
                if (replace) {
                    arrayOf(StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                } else {
                    arrayOf(StandardCopyOption.ATOMIC_MOVE)
                }
            Files.move(source, target, *options)
            faultForTests?.invoke(TraceIoPoint.BEFORE_PARENT_FSYNC)
            fsyncDirectory(parent)
        } catch (failure: HostCliException) {
            throw failure
        } catch (_: Exception) {
            throw HostCliException("COMMAND_TRACE_PERSIST_FAILED")
        }
    }

    fun requirePrivate(path: Path, code: String = "COMMAND_TRACE_PATH_UNSAFE") {
        if (
            Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.getPosixFilePermissions(path) != privateMode ||
                owner(path) != trustedOwner()
        ) {
            throw HostCliException(code)
        }
    }

    fun requireOwnedDirectory(path: Path): Path {
        val parent =
            path.toAbsolutePath().parent ?: throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
        if (
            Files.isSymbolicLink(parent) ||
                !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
                owner(parent) != trustedOwner()
        ) {
            throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
        }
        return parent
    }

    fun deleteDurably(path: Path) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) requirePrivate(path)
        Files.deleteIfExists(path)
        fsyncDirectory(requireOwnedDirectory(path))
    }

    fun quarantine(paths: List<Path>) {
        val existing = paths.filter { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }
        if (existing.isEmpty()) return
        val suffix = UUID.randomUUID().toString().replace("-", "")
        existing.forEach { path ->
            if (Files.isSymbolicLink(path)) throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
            Files.move(
                path,
                path.resolveSibling(".${path.fileName}.quarantine-$suffix"),
                StandardCopyOption.ATOMIC_MOVE,
            )
        }
        fsyncDirectory(requireOwnedDirectory(paths.first()))
    }

    fun resetTestSeams() {
        faultForTests = null
        ownerForTests = null
    }

    private fun owner(path: Path): String =
        ownerForTests?.invoke(path) ?: Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).name

    private fun trustedOwner(): String = Files.getOwner(Path.of("/proc/self")).name

    private fun fsyncDirectory(path: Path) {
        FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
    }
}

enum class TraceLifecycleState {
    ACTIVE,
    STOPPING,
    SEALED,
    RECEIPTED,
}

data class TraceLifecycle(
    val state: TraceLifecycleState,
    val sessionId: String,
    val headSha256: String,
    val eventCount: Int,
    val donorBootId: String,
    val candidateBootId: String,
    val donorEndMillis: Long,
    val candidateEndMillis: Long,
    val receiptSha256: String,
) {
    fun canonical(): String =
        listOf(
                state.name,
                sessionId,
                headSha256,
                eventCount,
                donorBootId,
                candidateBootId,
                donorEndMillis,
                candidateEndMillis,
                receiptSha256,
            )
            .joinToString("|", postfix = "\n")
}

object TraceLifecycleStore {
    private val pattern =
        Regex(
            "(ACTIVE|STOPPING|SEALED|RECEIPTED)\\|([0-9a-f]{32})\\|([0-9a-f]{64})\\|([0-9]+)\\|([A-Za-z0-9._-]{1,128})\\|([A-Za-z0-9._-]{1,128})\\|([0-9]+)\\|([0-9]+)\\|(-|[0-9a-f]{64})\\n"
        )

    fun create(baselinePath: Path, binding: TraceBinding) {
        val path = pathFor(baselinePath)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("COMMAND_TRACE_EXISTS")
        }
        write(path, active(binding), false)
    }

    fun read(baselinePath: Path): TraceLifecycle {
        val path = pathFor(baselinePath)
        TraceIo.requirePrivate(path)
        val values =
            pattern.matchEntire(Files.readString(path))?.groupValues
                ?: throw HostCliException("COMMAND_TRACE_STATE_INVALID")
        return TraceLifecycle(
            TraceLifecycleState.valueOf(values[1]),
            values[2],
            values[3],
            values[4].toInt(),
            values[5],
            values[6],
            values[7].toLong(),
            values[8].toLong(),
            values[9],
        )
    }

    fun transition(baselinePath: Path, expected: TraceLifecycleState, next: TraceLifecycle) {
        val current = read(baselinePath)
        if (current.state != expected || current.sessionId != next.sessionId) {
            throw HostCliException("COMMAND_TRACE_STATE_INVALID")
        }
        write(pathFor(baselinePath), next, true)
        if (read(baselinePath) != next) throw HostCliException("COMMAND_TRACE_STATE_INVALID")
    }

    fun pathFor(baselinePath: Path): Path =
        baselinePath.resolveSibling(".${baselinePath.fileName}.trace-state-v2")

    private fun active(binding: TraceBinding) =
        TraceLifecycle(
            TraceLifecycleState.ACTIVE,
            binding.sessionId,
            binding.headSha256,
            binding.eventCount,
            "-",
            "-",
            0,
            0,
            "-",
        )

    private fun write(path: Path, state: TraceLifecycle, replace: Boolean) =
        TraceIo.atomicWrite(path, state.canonical().toByteArray(), replace)
}
