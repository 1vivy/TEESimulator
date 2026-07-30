package org.matrix.TEESimulator.rka.bridge

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission

class LinuxProcessIdentitySource(private val procRoot: Path = Path.of("/proc")) :
    ProcessIdentitySource {
    override fun read(pid: Int): ObservedProcessIdentity {
        require(pid > 0)
        val processRoot = procRoot.resolve(pid.toString())
        val start =
            ProcStatParser.startTimeTicks(
                String(Files.readAllBytes(processRoot.resolve("stat")), StandardCharsets.US_ASCII)
            ) ?: throw IllegalArgumentException("malformed process stat")
        val rawCmdline = Files.readAllBytes(processRoot.resolve("cmdline"))
        val cmdline =
            rawCmdline
                .splitOnZero()
                .map { String(it, StandardCharsets.UTF_8) }
                .also { require(it.isNotEmpty() && it.none(String::isEmpty)) }
        rawCmdline.fill(0)
        val executablePath = processRoot.resolve("exe").toRealPath()
        val executable = executablePath.toString()
        val inode = (Files.getAttribute(executablePath, "unix:ino") as? Number)?.toLong()
        return ObservedProcessIdentity(start, cmdline, executable, inode)
    }

    private fun ByteArray.splitOnZero(): List<ByteArray> {
        if (isEmpty() || last() != 0.toByte()) return emptyList()
        val output = mutableListOf<ByteArray>()
        var start = 0
        for (index in indices) {
            if (this[index] == 0.toByte()) {
                if (index == start) return emptyList()
                output += copyOfRange(start, index)
                start = index + 1
            }
        }
        return output
    }
}

fun interface SocketMetadataSource {
    fun inspect(): SocketMetadata
}

class NioSocketMetadataSource(private val directory: Path, private val socket: Path) :
    SocketMetadataSource {
    override fun inspect(): SocketMetadata {
        require(!Files.isSymbolicLink(directory) && !Files.isSymbolicLink(socket))
        val directoryAttributes =
            Files.readAttributes(
                directory,
                PosixFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
        val socketAttributes =
            Files.readAttributes(socket, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        return SocketMetadata(
            directoryUid = unixId(directory, "unix:uid"),
            directoryGid = unixId(directory, "unix:gid"),
            directoryMode = directoryAttributes.permissions().toSet(),
            directorySymlink = directoryAttributes.isSymbolicLink,
            socketUid = unixId(socket, "unix:uid"),
            socketGid = unixId(socket, "unix:gid"),
            socketMode = socketAttributes.permissions().toSet(),
            socketSymlink = socketAttributes.isSymbolicLink,
        )
    }

    private fun unixId(path: Path, attribute: String): Int =
        (Files.getAttribute(path, attribute, LinkOption.NOFOLLOW_LINKS) as Number).toInt()
}

internal val ROOT_DIRECTORY_MODE: Set<PosixFilePermission> =
    setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE,
    )
