package org.matrix.TEESimulator.rka.bridge

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * Opaque authorization captured from the supervisor-owned immutable launch record. Construction is
 * private so a bridge consumer cannot nominate a peer process.
 */
class TrustedSidecarIdentity
private constructor(
    internal val snapshot: SupervisorSnapshot,
    private val launchNonce: String,
    private val recordInode: Long,
) {
    internal fun sameLaunch(other: TrustedSidecarIdentity): Boolean =
        snapshot == other.snapshot &&
            launchNonce == other.launchNonce &&
            recordInode == other.recordInode

    internal companion object {
        fun captured(
            snapshot: SupervisorSnapshot,
            launchNonce: String,
            recordInode: Long,
        ): TrustedSidecarIdentity = TrustedSidecarIdentity(snapshot, launchNonce, recordInode)
    }
}

internal interface TrustedSidecarIdentitySource {
    fun capture(): BridgeResult<TrustedSidecarIdentity>

    fun revalidate(identity: TrustedSidecarIdentity): BridgeResult<SupervisorSnapshot>
}

/**
 * Reads only the Task-3 protected runtime record. Task 11 must atomically publish this exact v1
 * schema at [RECORD_PATH] after exec identity is known:
 *
 * version, generation, launch_nonce (64 lowercase hex), uid, gid, pid, start_time_ticks,
 * executable_inode, executable_path and role (DONOR or CANDIDATE), one `key=value` line each in
 * that order. The argv authorized by the record is exactly `[executable_path, "--role",
 * role.lowercase()]`.
 */
internal class ProtectedSupervisorIdentitySource(
    private val processIdentity: ProcessIdentitySource = LinuxProcessIdentitySource(),
    private val recordPath: Path = RECORD_PATH,
    private val requiredUid: Int = 0,
    private val requiredGid: Int = 0,
) : TrustedSidecarIdentitySource {
    override fun capture(): BridgeResult<TrustedSidecarIdentity> = readValidated()

    override fun revalidate(identity: TrustedSidecarIdentity): BridgeResult<SupervisorSnapshot> =
        when (val current = readValidated()) {
            is BridgeResult.Failure -> current
            is BridgeResult.Success ->
                if (identity.sameLaunch(current.value)) {
                    BridgeResult.Success(current.value.snapshot)
                } else {
                    BridgeResult.Failure(BridgeError.TrustedStateChanged)
                }
        }

    private fun readValidated(): BridgeResult<TrustedSidecarIdentity> {
        if (!Files.exists(recordPath, LinkOption.NOFOLLOW_LINKS)) {
            return BridgeResult.Failure(BridgeError.TrustedStateMissing)
        }
        if (hasSymlinkAncestor(recordPath)) {
            return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
        }
        val parent =
            recordPath.parent ?: return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
        val before =
            runCatching { attributes(recordPath) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
                }
        val parentAttributes =
            runCatching { attributes(parent) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
                }
        if (
            !before.regular ||
                before.symlink ||
                before.uid != requiredUid ||
                before.gid != requiredGid ||
                before.mode != FILE_MODE ||
                before.size !in 1..MAX_RECORD_BYTES ||
                !parentAttributes.directory ||
                parentAttributes.symlink ||
                parentAttributes.uid != requiredUid ||
                parentAttributes.gid != requiredGid ||
                parentAttributes.mode != DIRECTORY_MODE
        ) {
            return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
        }
        if (recordPath == RECORD_PATH && !fixedProtectedDirectoriesAreValid()) {
            return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
        }
        val raw =
            runCatching { Files.readAllBytes(recordPath) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
                }
        try {
            if (raw.size.toLong() != before.size || raw.any { it < 0 }) {
                return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
            }
            val after =
                runCatching { attributes(recordPath) }
                    .getOrElse {
                        return BridgeResult.Failure(BridgeError.TrustedStateChanged)
                    }
            if (after != before) return BridgeResult.Failure(BridgeError.TrustedStateChanged)
            val fields =
                parse(String(raw, StandardCharsets.US_ASCII))
                    ?: return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
            val snapshot =
                SupervisorSnapshot(
                    generation = fields.generation,
                    uid = fields.uid,
                    gid = fields.gid,
                    pid = fields.pid,
                    startTimeTicks = fields.startTimeTicks,
                    cmdline = listOf(FIXED_EXECUTABLE, "--role", fields.role.lowercase()),
                    executablePath = FIXED_EXECUTABLE,
                    executableInode = fields.executableInode,
                )
            val observed =
                runCatching { processIdentity.read(snapshot.pid) }
                    .getOrElse {
                        return BridgeResult.Failure(BridgeError.PeerDied)
                    }
            if (
                snapshot.uid != 0 ||
                    snapshot.gid != 0 ||
                    !identityMatches(
                        PeerCredentials(snapshot.uid, snapshot.gid, snapshot.pid),
                        snapshot,
                        observed,
                    )
            ) {
                return BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
            }
            return BridgeResult.Success(
                TrustedSidecarIdentity.captured(snapshot, fields.launchNonce, before.inode)
            )
        } finally {
            raw.fill(0)
        }
    }

    private fun parse(text: String): RecordFields? {
        if (!text.endsWith("\n")) return null
        val lines = text.dropLast(1).split("\n")
        if (lines.size != KEYS.size) return null
        val values = LinkedHashMap<String, String>()
        for ((index, line) in lines.withIndex()) {
            val separator = line.indexOf('=')
            if (separator <= 0 || separator == line.lastIndex) return null
            val key = line.substring(0, separator)
            if (key != KEYS[index] || values.put(key, line.substring(separator + 1)) != null) {
                return null
            }
        }
        if (values.getValue("version") != "1") return null
        val nonce = values.getValue("launch_nonce")
        if (nonce.length != 64 || nonce.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
        val role = values.getValue("role")
        if (role != "DONOR" && role != "CANDIDATE") return null
        if (values.getValue("executable_path") != FIXED_EXECUTABLE) return null
        return RecordFields(
            generation =
                values.getValue("generation").toLongOrNull()?.takeIf { it >= 0 } ?: return null,
            launchNonce = nonce,
            uid = values.getValue("uid").toIntOrNull()?.takeIf { it == 0 } ?: return null,
            gid = values.getValue("gid").toIntOrNull()?.takeIf { it == 0 } ?: return null,
            pid = values.getValue("pid").toIntOrNull()?.takeIf { it > 0 } ?: return null,
            startTimeTicks =
                values.getValue("start_time_ticks").toLongOrNull()?.takeIf { it >= 0 }
                    ?: return null,
            executableInode =
                values.getValue("executable_inode").toLongOrNull()?.takeIf { it >= 0 }
                    ?: return null,
            role = role,
        )
    }

    private fun attributes(path: Path): RecordAttributes {
        val values =
            Files.readAttributes(
                path,
                "unix:ino,uid,gid,mode,size,isRegularFile,isDirectory,isSymbolicLink",
                LinkOption.NOFOLLOW_LINKS,
            )
        return RecordAttributes(
            inode = (values.getValue("ino") as Number).toLong(),
            uid = (values.getValue("uid") as Number).toInt(),
            gid = (values.getValue("gid") as Number).toInt(),
            mode = (values.getValue("mode") as Number).toInt() and 0x1ff,
            size = (values.getValue("size") as Number).toLong(),
            regular = values.getValue("isRegularFile") as Boolean,
            directory = values.getValue("isDirectory") as Boolean,
            symlink = values.getValue("isSymbolicLink") as Boolean,
        )
    }

    private fun hasSymlinkAncestor(path: Path): Boolean {
        var current: Path? = path.toAbsolutePath().root
        for (component in path.toAbsolutePath()) {
            current = requireNotNull(current).resolve(component)
            if (Files.isSymbolicLink(current)) return true
        }
        return false
    }

    private fun fixedProtectedDirectoriesAreValid(): Boolean =
        listOf(
                Path.of("/data/adb/teesimulator-rka"),
                Path.of("/data/adb/teesimulator-rka/run"),
                Path.of("/data/adb/teesimulator-rka/run/pids"),
            )
            .all { path ->
                runCatching {
                        val value = attributes(path)
                        value.directory &&
                            !value.symlink &&
                            value.uid == requiredUid &&
                            value.gid == requiredGid &&
                            value.mode == DIRECTORY_MODE
                    }
                    .getOrDefault(false)
            }

    private data class RecordFields(
        val generation: Long,
        val launchNonce: String,
        val uid: Int,
        val gid: Int,
        val pid: Int,
        val startTimeTicks: Long,
        val executableInode: Long,
        val role: String,
    )

    private data class RecordAttributes(
        val inode: Long,
        val uid: Int,
        val gid: Int,
        val mode: Int,
        val size: Long,
        val regular: Boolean,
        val directory: Boolean,
        val symlink: Boolean,
    )

    internal companion object {
        val RECORD_PATH: Path = Path.of("/data/adb/teesimulator-rka/run/pids/sidecar.identity")
        const val FIXED_EXECUTABLE = "/data/adb/teesimulator-rka/bin/rka-sidecar"
        private const val DIRECTORY_MODE = 0x1c0
        private const val FILE_MODE = 0x180
        private const val MAX_RECORD_BYTES = 4096L
        private val KEYS =
            listOf(
                "version",
                "generation",
                "launch_nonce",
                "uid",
                "gid",
                "pid",
                "start_time_ticks",
                "executable_inode",
                "executable_path",
                "role",
            )
    }
}

private class TestTrustedSidecarIdentitySource(
    private val expected: () -> SupervisorSnapshot,
    private val processIdentity: ProcessIdentitySource,
) : TrustedSidecarIdentitySource {
    private lateinit var capturedSnapshot: SupervisorSnapshot
    private var validations = 0

    override fun capture(): BridgeResult<TrustedSidecarIdentity> {
        capturedSnapshot = expected()
        return BridgeResult.Success(
            TrustedSidecarIdentity.captured(capturedSnapshot, TEST_NONCE, 1)
        )
    }

    override fun revalidate(identity: TrustedSidecarIdentity): BridgeResult<SupervisorSnapshot> {
        val snapshot = if (validations++ == 0) capturedSnapshot else expected()
        if (identity.snapshot.generation != snapshot.generation) {
            return BridgeResult.Failure(BridgeError.TrustedStateChanged)
        }
        val observed =
            runCatching { processIdentity.read(snapshot.pid) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.PeerDied)
                }
        return if (
            identityMatches(
                PeerCredentials(snapshot.uid, snapshot.gid, snapshot.pid),
                snapshot,
                observed,
            )
        ) {
            BridgeResult.Success(snapshot)
        } else {
            BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
        }
    }

    private companion object {
        const val TEST_NONCE = "0000000000000000000000000000000000000000000000000000000000000000"
    }
}

@JvmSynthetic
internal fun testTrustedSidecarIdentitySource(
    expected: () -> SupervisorSnapshot,
    processIdentity: ProcessIdentitySource,
): TrustedSidecarIdentitySource = TestTrustedSidecarIdentitySource(expected, processIdentity)
