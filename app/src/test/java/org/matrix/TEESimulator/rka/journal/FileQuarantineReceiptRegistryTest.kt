package org.matrix.TEESimulator.rka.journal

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class FileQuarantineReceiptRegistryTest {
    @Test
    fun keyedReceiptsCoexistAndCreateNeverOverwrites() {
        val parent = privateDirectory()
        val owner = Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Int
        val registry = FileQuarantineReceiptRegistry(parent.resolve("receipts"), owner)
        val keyA = ByteArray(32) { 1 }
        val keyB = ByteArray(32) { 2 }
        val receiptA = ByteArray(33) { 3 }
        val receiptB = ByteArray(33) { 4 }

        assertTrue(registry.create(keyA, receiptA))
        assertTrue(registry.create(keyB, receiptB))
        assertFalse(registry.create(keyA, ByteArray(33) { 9 }))
        assertArrayEquals(receiptA, registry.read(keyA))
        assertArrayEquals(receiptB, registry.read(keyB))
    }

    @Test
    fun registryRejectsSymlinksWeakModesAndCapacityOverflow() {
        val parent = privateDirectory()
        val owner = Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Int
        val directory = parent.resolve("receipts")
        val registry = FileQuarantineReceiptRegistry(directory, owner)
        repeat(64) { index ->
            val key = ByteArray(32)
            key[0] = index.toByte()
            assertTrue(registry.create(key, ByteArray(33) { index.toByte() }))
        }
        assertThrows(IllegalArgumentException::class.java) {
            registry.create(ByteArray(32) { 65 }, ByteArray(33))
        }

        val weak = parent.resolve("weak")
        Files.createDirectory(weak)
        Files.setPosixFilePermissions(weak, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertThrows(IllegalArgumentException::class.java) {
            FileQuarantineReceiptRegistry(weak.resolve("receipts"), owner)
        }

        val linked = parent.resolve("linked")
        Files.createSymbolicLink(linked, directory)
        assertThrows(IllegalArgumentException::class.java) {
            FileQuarantineReceiptRegistry(linked, owner)
        }
    }

    @Test
    fun startupDeterministicallyRemovesOnlyValidatedStaleTemps() {
        val parent = privateDirectory()
        val owner = Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Int
        val directory = parent.resolve("receipts")
        Files.createDirectory(
            directory,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
        )
        val stale = directory.resolve(".receipt-stale.tmp")
        Files.createFile(
            stale,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        )
        Files.write(stale, ByteArray(33) { 7 })

        FileQuarantineReceiptRegistry(directory, owner)

        assertFalse(Files.exists(stale, LinkOption.NOFOLLOW_LINKS))
    }

    private fun privateDirectory() =
        Files.createTempDirectory(
            "quarantine-receipts-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
        )
}
