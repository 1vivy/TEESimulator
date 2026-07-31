package org.matrix.TEESimulator.rka.journal

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import org.matrix.TEESimulator.rka.broker.QuarantineReceiptStore

class FileQuarantineReceiptRegistry
internal constructor(private val directory: Path, private val ownerUid: Int = 0) :
    QuarantineReceiptStore {
    init {
        ensureDirectory()
    }

    override fun read(key: ByteArray): ByteArray? {
        val target = target(key)
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return null
        validateReceipt(target)
        return Files.readAllBytes(target).also { require(it.size == RECEIPT_BYTES) }
    }

    override fun create(key: ByteArray, receipt: ByteArray): Boolean {
        require(receipt.size == RECEIPT_BYTES)
        validateDirectory(directory)
        val target = target(key)
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return false
        require(retainedCountAndCleanTemps() < MAX_RECEIPTS)
        val temporary = Files.createTempFile(directory, TEMP_PREFIX, TEMP_SUFFIX, fileMode)
        try {
            FileChannel.open(temporary, StandardOpenOption.WRITE).use { channel ->
                val buffer = ByteBuffer.wrap(receipt)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            try {
                Files.createLink(target, temporary)
            } catch (_: FileAlreadyExistsException) {
                return false
            }
            fsyncDirectory(directory)
            validateReceipt(target)
            return true
        } finally {
            Files.deleteIfExists(temporary)
            fsyncDirectory(directory)
        }
    }

    private fun retainedCountAndCleanTemps(): Int {
        var retained = 0
        Files.newDirectoryStream(directory).use { entries ->
            entries.forEach { entry ->
                val name = entry.fileName.toString()
                when {
                    RECEIPT_NAME.matches(name) -> {
                        validateReceipt(entry)
                        retained++
                    }
                    name.startsWith(TEMP_PREFIX) && name.endsWith(TEMP_SUFFIX) -> {
                        validateReceipt(entry)
                        Files.delete(entry)
                    }
                    else -> throw IllegalStateException("unexpected receipt registry entry")
                }
            }
        }
        fsyncDirectory(directory)
        return retained
    }

    private fun target(key: ByteArray): Path {
        require(key.size == KEY_BYTES)
        return directory.resolve(key.joinToString("") { "%02x".format(it) } + RECEIPT_SUFFIX)
    }

    private fun ensureDirectory() {
        val parent = requireNotNull(directory.parent)
        validateDirectory(parent)
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(directory, directoryMode)
            fsyncDirectory(parent)
        }
        validateDirectory(directory)
        require(retainedCountAndCleanTemps() <= MAX_RECEIPTS)
    }

    private fun validateDirectory(path: Path) {
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
        require(Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) == ownerUid)
        require(Files.getPosixFilePermissions(path) == PRIVATE_DIRECTORY_PERMISSIONS)
    }

    private fun validateReceipt(path: Path) {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        require(Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) == ownerUid)
        require(Files.getPosixFilePermissions(path) == PRIVATE_FILE_PERMISSIONS)
        require(Files.size(path) == RECEIPT_BYTES.toLong())
    }

    private fun fsyncDirectory(path: Path) {
        FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
    }

    companion object {
        private const val KEY_BYTES = 32
        private const val RECEIPT_BYTES = 33
        private const val MAX_RECEIPTS = 64
        private const val RECEIPT_SUFFIX = ".receipt"
        private const val TEMP_PREFIX = ".receipt-"
        private const val TEMP_SUFFIX = ".tmp"
        private val RECEIPT_NAME = Regex("[0-9a-f]{64}\\.receipt")
        private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
        private val PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
        private val directoryMode =
            PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS)
        private val fileMode = PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS)

        fun production(root: Path): FileQuarantineReceiptRegistry =
            FileQuarantineReceiptRegistry(root.resolve("rka/journal/quarantine-receipts"))
    }
}
