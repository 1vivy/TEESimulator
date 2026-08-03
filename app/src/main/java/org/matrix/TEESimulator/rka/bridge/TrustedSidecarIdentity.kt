package org.matrix.TEESimulator.rka.bridge

import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.Closeable
import java.io.FileDescriptor
import java.nio.charset.StandardCharsets
import org.matrix.TEESimulator.logging.SystemLogger

internal sealed interface ProductionPeerAuthorization : Closeable {
    fun authenticate(credentials: PeerCredentials): BridgeResult<SupervisorSnapshot>
}

internal enum class BrokerSidecarRole(val recordValue: String, val argvValue: String) {
    DONOR("DONOR", "donor"),
    CANDIDATE("CANDIDATE", "candidate"),
}

internal fun captureProductionPeerAuthorization(
    expectedRole: BrokerSidecarRole
): BridgeResult<ProductionPeerAuthorization> = FixedSupervisorAuthorization.capture(expectedRole)

internal data class SupervisorRecordFields(
    val generation: Long,
    val launchNonce: String,
    val uid: Int,
    val gid: Int,
    val pid: Int,
    val startTimeTicks: Long,
    val executableInode: Long,
    val role: BrokerSidecarRole,
) {
    fun snapshotFor(expectedRole: BrokerSidecarRole): SupervisorSnapshot? {
        if (role != expectedRole) return null
        return snapshot()
    }

    fun snapshot(): SupervisorSnapshot =
        SupervisorSnapshot(
            generation = generation,
            uid = uid,
            gid = gid,
            pid = pid,
            startTimeTicks = startTimeTicks,
            cmdline = listOf(FIXED_EXECUTABLE, "--role", role.argvValue),
            executablePath = FIXED_EXECUTABLE,
            executableInode = executableInode,
        )

    companion object {
        const val FIXED_EXECUTABLE = "/data/adb/teesimulator-rka/bin/rka-sidecar"
    }
}

internal object SupervisorRecordTextParser {
    fun parse(text: String): SupervisorRecordFields? {
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
        val role =
            BrokerSidecarRole.entries.singleOrNull { it.recordValue == values.getValue("role") }
                ?: return null
        if (values.getValue("executable_path") != SupervisorRecordFields.FIXED_EXECUTABLE) {
            return null
        }
        return SupervisorRecordFields(
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

private object FixedSupervisorAuthorization {
    fun capture(expectedRole: BrokerSidecarRole): BridgeResult<ProductionPeerAuthorization> {
        val opened = TrustedRecordHandle.open()
        if (opened is BridgeResult.Failure) return opened
        val handle = (opened as BridgeResult.Success).value
        val record = handle.readStable(initial = true)
        if (record is BridgeResult.Failure) {
            handle.close()
            return record
        }
        val initial = (record as BridgeResult.Success).value
        val snapshot = initial.snapshotFor(expectedRole)
        if (snapshot == null || !processMatches(snapshot)) {
            SystemLogger.warning("RKA bridge peer rejected: stage=supervisor category=identity")
            handle.close()
            return BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
        }
        return BridgeResult.Success(DescriptorPeerAuthorization(handle, initial, expectedRole))
    }

    private fun processMatches(snapshot: SupervisorSnapshot): Boolean {
        val observed =
            runCatching { LinuxProcessIdentitySource().read(snapshot.pid) }.getOrNull()
                ?: return false
        return identityMatches(
            PeerCredentials(snapshot.uid, snapshot.gid, snapshot.pid),
            snapshot,
            observed,
        )
    }
}

private class DescriptorPeerAuthorization(
    private val handle: TrustedRecordHandle,
    private val initial: SupervisorRecordFields,
    private val expectedRole: BrokerSidecarRole,
) : ProductionPeerAuthorization {
    override fun authenticate(credentials: PeerCredentials): BridgeResult<SupervisorSnapshot> {
        val current = handle.readStable(initial = false)
        if (current is BridgeResult.Failure) return current
        val fields = (current as BridgeResult.Success).value
        if (fields != initial) return BridgeResult.Failure(BridgeError.TrustedStateChanged)
        val snapshot = fields.snapshotFor(expectedRole) ?: return identityFailure("role")
        val observed =
            runCatching { LinuxProcessIdentitySource().read(snapshot.pid) }
                .getOrElse {
                    SystemLogger.warning(
                        "RKA bridge peer rejected: stage=authenticate category=supervisor_unreadable"
                    )
                    return BridgeResult.Failure(BridgeError.PeerDied)
                }
        val admitted =
            if (identityMatches(credentials, snapshot, observed)) {
                snapshot
            } else {
                val provisioningObserved =
                    runCatching { LinuxProcessIdentitySource().read(credentials.pid) }
                        .getOrElse {
                            return identityFailure("peer_unreadable")
                        }
                provisioningPeerSnapshot(expectedRole, credentials, snapshot, provisioningObserved)
                    ?: return identityFailure(
                        provisioningPeerMismatchCategory(
                            expectedRole,
                            credentials,
                            snapshot,
                            provisioningObserved,
                        )
                    )
            }
        return BridgeResult.Success(admitted)
    }

    private fun identityFailure(category: String): BridgeResult.Failure {
        SystemLogger.warning("RKA bridge peer rejected: stage=authenticate category=$category")
        return BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
    }

    override fun close() {
        handle.close()
    }
}

internal fun provisioningPeerSnapshot(
    expectedRole: BrokerSidecarRole,
    credentials: PeerCredentials,
    supervised: SupervisorSnapshot,
    observed: ObservedProcessIdentity,
): SupervisorSnapshot? {
    if (
        expectedRole != BrokerSidecarRole.DONOR ||
            credentials.uid != supervised.uid ||
            credentials.gid != supervised.gid
    ) {
        return null
    }
    val expectedCommand = listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "provision")
    if (
        observed.cmdline != expectedCommand ||
            observed.executablePath != supervised.executablePath ||
            supervised.executableInode == null ||
            observed.executableInode != supervised.executableInode
    ) {
        return null
    }
    return supervised.copy(
        pid = credentials.pid,
        startTimeTicks = observed.startTimeTicks,
        cmdline = observed.cmdline,
    )
}

private fun provisioningPeerMismatchCategory(
    expectedRole: BrokerSidecarRole,
    credentials: PeerCredentials,
    supervised: SupervisorSnapshot,
    observed: ObservedProcessIdentity,
): String =
    when {
        expectedRole != BrokerSidecarRole.DONOR -> "provision_role"
        credentials.uid != supervised.uid || credentials.gid != supervised.gid ->
            "provision_credentials"
        observed.executablePath != supervised.executablePath ->
            provisioningExecutableCategory(observed.executablePath)
        supervised.executableInode == null ||
            observed.executableInode != supervised.executableInode -> "provision_inode"
        observed.cmdline == supervised.cmdline -> "provision_cmdline_supervised"
        observed.cmdline.size != 2 -> provisioningCommandShape(observed.cmdline)
        observed.cmdline.first() != SupervisorRecordFields.FIXED_EXECUTABLE ->
            "provision_cmdline_executable"
        observed.cmdline.last() != "provision" -> "provision_cmdline_action"
        else -> "provision_identity"
    }

private fun provisioningExecutableCategory(executablePath: String): String =
    when (executablePath) {
        SupervisorRecordFields.FIXED_EXECUTABLE -> "provision_executable_runtime"
        "/system/bin/sh" -> "provision_executable_shell"
        "/system/bin/nsenter",
        "/system/bin/toybox" -> "provision_executable_namespace_tool"
        "/system/bin/app_process64" -> "provision_executable_app_process64"
        "/data/adb/ksud",
        "/data/adb/ksu/bin/ksud" -> "provision_executable_ksud"
        else -> "provision_executable_other"
    }

private fun provisioningCommandShape(cmdline: List<String>): String {
    val arity = cmdline.size.coerceAtMost(6)
    val shape =
        cmdline.take(6).joinToString(separator = "_") {
            when (it) {
                SupervisorRecordFields.FIXED_EXECUTABLE -> "runtime"
                "provision" -> "provision"
                "--role" -> "role"
                "donor" -> "donor"
                "candidate" -> "candidate"
                else -> "other"
            }
        }
    return "provision_cmdline_${arity}_$shape"
}

private class TrustedRecordHandle
private constructor(
    private val directories: List<HeldDirectory>,
    private val recordDescriptor: FileDescriptor,
    private val recordSignature: RecordSignature,
) : Closeable {
    fun readStable(initial: Boolean): BridgeResult<SupervisorRecordFields> {
        val changedError =
            if (initial) BridgeError.TrustedStateInvalid else BridgeError.TrustedStateChanged
        if (!chainStillNamed() || !recordStillNamed()) {
            return BridgeResult.Failure(changedError)
        }
        val before =
            runCatching { RecordSignature.from(Os.fstat(recordDescriptor)) }
                .getOrElse {
                    return BridgeResult.Failure(changedError)
                }
        if (before != recordSignature) return BridgeResult.Failure(changedError)
        val raw = ByteArray(before.size.toInt())
        try {
            var offset = 0
            while (offset < raw.size) {
                val read =
                    try {
                        Os.pread(recordDescriptor, raw, offset, raw.size - offset, offset.toLong())
                    } catch (_: Exception) {
                        return BridgeResult.Failure(changedError)
                    }
                if (read <= 0) return BridgeResult.Failure(changedError)
                offset += read
            }
            val overflow = ByteArray(1)
            if (
                runCatching { Os.pread(recordDescriptor, overflow, 0, 1, raw.size.toLong()) }
                    .getOrDefault(-1) != 0
            ) {
                return BridgeResult.Failure(changedError)
            }
            val after =
                runCatching { RecordSignature.from(Os.fstat(recordDescriptor)) }
                    .getOrElse {
                        return BridgeResult.Failure(changedError)
                    }
            if (
                after != before ||
                    after != recordSignature ||
                    !chainStillNamed() ||
                    !recordStillNamed()
            ) {
                return BridgeResult.Failure(changedError)
            }
            if (raw.any { it < 0 }) return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
            val parsed = SupervisorRecordTextParser.parse(String(raw, StandardCharsets.US_ASCII))
            return if (parsed == null) {
                BridgeResult.Failure(BridgeError.TrustedStateInvalid)
            } else {
                BridgeResult.Success(parsed)
            }
        } finally {
            raw.fill(0)
        }
    }

    private fun chainStillNamed(): Boolean {
        if (directories.isEmpty()) return false
        for (directory in directories) {
            val held =
                runCatching { DirectorySignature.from(Os.fstat(directory.descriptor)) }
                    .getOrElse {
                        return false
                    }
            if (held != directory.signature) return false
        }
        for (index in 1 until directories.size) {
            val parent = directories[index - 1]
            val child = directories[index]
            val named =
                runCatching {
                        DirectorySignature.from(
                            Os.lstat("${descriptorPath(parent.descriptor)}/${child.name}")
                        )
                    }
                    .getOrElse {
                        return false
                    }
            if (named != child.signature) return false
        }
        return true
    }

    private fun recordStillNamed(): Boolean {
        val parent = directories.lastOrNull() ?: return false
        val named =
            runCatching {
                    RecordSignature.from(
                        Os.lstat("${descriptorPath(parent.descriptor)}/$RECORD_NAME")
                    )
                }
                .getOrElse {
                    return false
                }
        return named == recordSignature
    }

    override fun close() {
        runCatching { Os.close(recordDescriptor) }
        directories.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
    }

    companion object {
        fun open(): BridgeResult<TrustedRecordHandle> {
            val held = mutableListOf<HeldDirectory>()
            var record: FileDescriptor? = null
            try {
                val root = openDirectory("/")
                held += HeldDirectory("", root, DirectorySignature.from(Os.fstat(root)))
                for (name in COMPONENTS) {
                    val descriptor =
                        openDirectory("${descriptorPath(held.last().descriptor)}/$name")
                    val signature = DirectorySignature.from(Os.fstat(descriptor))
                    if (!signature.directory) {
                        Os.close(descriptor)
                        return closeAndFail(held, BridgeError.TrustedStateInvalid)
                    }
                    held += HeldDirectory(name, descriptor, signature)
                }
                if (!protectedDirectoriesAreValid(held)) {
                    return closeAndFail(held, BridgeError.TrustedStateInvalid)
                }
                record =
                    Os.open(
                        "${descriptorPath(held.last().descriptor)}/$RECORD_NAME",
                        OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                        0,
                    )
                val signature = RecordSignature.from(Os.fstat(record))
                if (
                    !signature.regular ||
                        signature.uid != 0 ||
                        signature.gid != 0 ||
                        signature.mode != FILE_MODE ||
                        signature.size !in 1..MAX_RECORD_BYTES
                ) {
                    Os.close(record)
                    record = null
                    return closeAndFail(held, BridgeError.TrustedStateInvalid)
                }
                return BridgeResult.Success(TrustedRecordHandle(held.toList(), record, signature))
            } catch (error: android.system.ErrnoException) {
                record?.let { runCatching { Os.close(it) } }
                held.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
                return BridgeResult.Failure(
                    if (error.errno == OsConstants.ENOENT) {
                        BridgeError.TrustedStateMissing
                    } else {
                        BridgeError.TrustedStateInvalid
                    }
                )
            } catch (_: Exception) {
                record?.let { runCatching { Os.close(it) } }
                held.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
                return BridgeResult.Failure(BridgeError.TrustedStateInvalid)
            }
        }

        private fun openDirectory(path: String): FileDescriptor =
            Os.open(
                path,
                OsConstants.O_RDONLY or
                    O_DIRECTORY or
                    OsConstants.O_NOFOLLOW or
                    OsConstants.O_CLOEXEC,
                0,
            )

        private fun protectedDirectoriesAreValid(held: List<HeldDirectory>): Boolean =
            held
                .filter { it.name in PROTECTED_COMPONENTS }
                .all {
                    it.signature.directory &&
                        it.signature.uid == 0 &&
                        it.signature.gid == 0 &&
                        it.signature.mode == DIRECTORY_MODE
                }

        private fun closeAndFail(
            held: List<HeldDirectory>,
            error: BridgeError,
        ): BridgeResult.Failure {
            held.asReversed().forEach { runCatching { Os.close(it.descriptor) } }
            return BridgeResult.Failure(error)
        }

        private val COMPONENTS = listOf("data", "adb", "teesimulator-rka", "run", "pids")
        private val PROTECTED_COMPONENTS = setOf("teesimulator-rka", "run", "pids")
        private const val RECORD_NAME = "sidecar.identity"
        private const val DIRECTORY_MODE = 0x1c0
        private const val FILE_MODE = 0x180
        private const val MAX_RECORD_BYTES = 4096L
        private const val O_DIRECTORY = 0x4000
    }
}

private data class HeldDirectory(
    val name: String,
    val descriptor: FileDescriptor,
    val signature: DirectorySignature,
)

private data class DirectorySignature(
    val device: Long,
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val directory: Boolean,
) {
    companion object {
        fun from(stat: StructStat): DirectorySignature =
            DirectorySignature(
                stat.st_dev,
                stat.st_ino,
                stat.st_uid,
                stat.st_gid,
                stat.st_mode and 0x1ff,
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR,
            )
    }
}

private data class RecordSignature(
    val device: Long,
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val size: Long,
    val modifiedSeconds: Long,
    val modifiedNanos: Long,
    val changedSeconds: Long,
    val changedNanos: Long,
    val regular: Boolean,
) {
    companion object {
        fun from(stat: StructStat): RecordSignature =
            RecordSignature(
                stat.st_dev,
                stat.st_ino,
                stat.st_uid,
                stat.st_gid,
                stat.st_mode and 0x1ff,
                stat.st_size,
                stat.st_mtim.tv_sec,
                stat.st_mtim.tv_nsec,
                stat.st_ctim.tv_sec,
                stat.st_ctim.tv_nsec,
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFREG,
            )
    }
}

private fun descriptorPath(descriptor: FileDescriptor): String =
    "/proc/self/fd/${descriptorNumber(descriptor)}"

private fun descriptorNumber(descriptor: FileDescriptor): Int =
    FileDescriptor::class.java.getDeclaredMethod("getInt$").invoke(descriptor) as Int
