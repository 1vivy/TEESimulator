package org.matrix.TEESimulator.rka.bridge

import java.nio.file.attribute.PosixFilePermission

data class PeerCredentials(val uid: Int, val gid: Int, val pid: Int) {
    init {
        require(uid >= 0 && gid >= 0 && pid > 0)
    }
}

data class SupervisorSnapshot(
    val generation: Long,
    val uid: Int,
    val gid: Int,
    val pid: Int,
    val startTimeTicks: Long,
    val cmdline: List<String>,
    val executablePath: String,
    val executableInode: Long?,
) {
    init {
        require(generation >= 0 && uid >= 0 && gid >= 0 && pid > 0 && startTimeTicks >= 0)
        require(cmdline.isNotEmpty() && cmdline.none(String::isEmpty))
        require(executablePath.startsWith("/"))
        require(executableInode == null || executableInode >= 0)
    }
}

data class ObservedProcessIdentity(
    val startTimeTicks: Long,
    val cmdline: List<String>,
    val executablePath: String,
    val executableInode: Long?,
)

fun interface ProcessIdentitySource {
    fun read(pid: Int): ObservedProcessIdentity
}

object ProcStatParser {
    fun startTimeTicks(stat: String): Long? {
        val close = stat.lastIndexOf(')')
        if (close <= 1 || close + 2 >= stat.length || stat[close + 1] != ' ') return null
        val fields = stat.substring(close + 2).trim().split(Regex(" +"))
        if (fields.size <= 19 || fields[0].length != 1) return null
        return fields[19].toLongOrNull()?.takeIf { it >= 0 }
    }
}

data class SocketMetadata(
    val directoryUid: Int,
    val directoryGid: Int,
    val directoryMode: Set<PosixFilePermission>,
    val directorySymlink: Boolean,
    val socketUid: Int,
    val socketGid: Int,
    val socketMode: Set<PosixFilePermission>,
    val socketSymlink: Boolean,
) {
    companion object {
        fun secureRootOwned() =
            SocketMetadata(
                0,
                0,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ),
                false,
                0,
                0,
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                false,
            )
    }
}

object SocketPolicy {
    private val directoryMode =
        setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
    private val socketMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun validate(metadata: SocketMetadata): BridgeResult<Unit> =
        if (
            metadata.directoryUid == 0 &&
                metadata.directoryGid == 0 &&
                metadata.directoryMode == directoryMode &&
                !metadata.directorySymlink &&
                metadata.socketUid == 0 &&
                metadata.socketGid == 0 &&
                metadata.socketMode == socketMode &&
                !metadata.socketSymlink
        ) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.SocketPolicy)
        }
}

internal fun identityMatches(
    credentials: PeerCredentials,
    expected: SupervisorSnapshot,
    observed: ObservedProcessIdentity,
): Boolean =
    credentials.uid == expected.uid &&
        credentials.gid == expected.gid &&
        credentials.pid == expected.pid &&
        observed.startTimeTicks == expected.startTimeTicks &&
        observed.cmdline == expected.cmdline &&
        observed.executablePath == expected.executablePath &&
        (expected.executableInode == null || observed.executableInode == expected.executableInode)
