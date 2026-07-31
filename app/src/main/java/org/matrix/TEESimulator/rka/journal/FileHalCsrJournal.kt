package org.matrix.TEESimulator.rka.journal

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest

class FileHalCsrJournal(private val root: Path) {
    fun record(batchId: RkpBatchId, csr: ByteArray) {
        require(csr.isNotEmpty() && csr.size <= 1_048_576)
        val record =
            ByteBuffer.allocate(4 + 16 + 32 + 4 + csr.size)
                .putInt(0x524b4331)
                .put(batchId.copyBytes())
                .put(MessageDigest.getInstance("SHA-256").digest(csr))
                .putInt(csr.size)
                .put(csr)
                .array()
        val directory = root.resolve("rka/journal")
        require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))
        require(Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS) == 0)
        require(
            Files.getPosixFilePermissions(directory) ==
                PosixFilePermissions.fromString("rwx------")
        )
        val mode =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        val temporary = Files.createTempFile(directory, ".hal-csr-", ".tmp", mode)
        try {
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(record))
                it.force(true)
            }
            Files.move(
                temporary,
                directory.resolve("hal-csr.journal"),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }
}
