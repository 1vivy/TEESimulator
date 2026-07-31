package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class EvidenceStoreTransactionTest {
    @Test
    fun cborSymlinkRejectsBeforeJsonIsPublished() {
        val root = Files.createTempDirectory("evidence-symlink-")
        val json = root.resolve("receipt.json")
        val target = Files.writeString(root.resolve("target"), "unchanged")
        Files.createSymbolicLink(root.resolve("receipt.json.cbor"), target)

        assertThrows(HostCliException::class.java) { EvidenceStore.write(json, "{}\n") }

        assertFalse(Files.exists(json))
        assertEquals("unchanged", Files.readString(target))
    }

    @Test
    fun jsonSymlinkRejectsBeforeCborIsPublished() {
        val root = Files.createTempDirectory("evidence-json-symlink-")
        val json = root.resolve("receipt.json")
        val target = Files.writeString(root.resolve("target"), "unchanged")
        Files.createSymbolicLink(json, target)

        assertThrows(HostCliException::class.java) { EvidenceStore.write(json, "{}\n") }

        assertFalse(Files.exists(root.resolve("receipt.json.cbor")))
        assertEquals("unchanged", Files.readString(target))
    }

    @Test
    fun failureAtEveryCommitPointPublishesNeitherNewFile() {
        for (point in EvidenceCommitPoint.entries) {
            val root = Files.createTempDirectory("evidence-failure-")
            val json = root.resolve("receipt.json")

            assertThrows(HostCliException::class.java) {
                EvidenceStore.write(json, "new\n") {
                    if (it == point) throw HostCliException("INJECTED")
                }
            }

            assertFalse(Files.exists(json))
            assertFalse(Files.exists(root.resolve("receipt.json.cbor")))
        }
    }

    @Test
    fun interruptionAtEveryCommitPointRecoversOldCoherentPair() {
        for (point in EvidenceCommitPoint.entries) {
            val root = Files.createTempDirectory("evidence-interruption-")
            val json = root.resolve("receipt.json")
            EvidenceStore.write(json, "old\n")

            assertThrows(SimulatedInterruption::class.java) {
                EvidenceStore.write(json, "new\n") {
                    if (it == point) throw SimulatedInterruption()
                }
            }

            assertEquals("old\n", EvidenceStore.read(json))
        }
    }

    private class SimulatedInterruption : Error()
}
