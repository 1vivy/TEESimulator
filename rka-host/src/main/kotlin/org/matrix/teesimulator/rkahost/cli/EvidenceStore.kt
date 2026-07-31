package org.matrix.teesimulator.rkahost.cli

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission

object EvidenceStore {
    private val fileMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun write(jsonPath: Path, receipt: String) {
        if (jsonPath.fileName.toString().isBlank()) throw HostCliException("EVIDENCE_PATH_UNSAFE")
        val cborPath = jsonPath.resolveSibling("${jsonPath.fileName}.cbor")
        atomicWrite(jsonPath, receipt.toByteArray())
        atomicWrite(cborPath, encodeText(receipt))
    }

    private fun atomicWrite(path: Path, bytes: ByteArray) {
        val absolute = path.toAbsolutePath()
        val parent = absolute.parent ?: throw HostCliException("EVIDENCE_PATH_UNSAFE")
        if (
            Files.isSymbolicLink(path) ||
                !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(parent)
        ) {
            throw HostCliException("EVIDENCE_PATH_UNSAFE")
        }
        val temporary = Files.createTempFile(parent, ".evidence-", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, fileMode)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(bytes))
                it.force(true)
            }
            Files.move(
                temporary,
                absolute,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun encodeText(value: String): ByteArray {
        val payload = value.toByteArray()
        val prefix =
            when {
                payload.size < 24 -> byteArrayOf((0x60 + payload.size).toByte())
                payload.size <= 0xff -> byteArrayOf(0x78, payload.size.toByte())
                payload.size <= 0xffff ->
                    byteArrayOf(0x79, (payload.size shr 8).toByte(), payload.size.toByte())
                else ->
                    byteArrayOf(
                        0x7a,
                        (payload.size shr 24).toByte(),
                        (payload.size shr 16).toByte(),
                        (payload.size shr 8).toByte(),
                        payload.size.toByte(),
                    )
            }
        return prefix + payload
    }
}
