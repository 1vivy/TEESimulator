package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DevicePairCliTest {
    @Test
    fun rejectsSameSerial() {
        val root = Files.createTempDirectory("pair-cli-")
        val profile = Files.writeString(root.resolve("profile.json"), "{}")
        val exit =
            HostCli.run(
                arrayOf(
                    "device-pair",
                    "bind",
                    "--donor",
                    "SERIAL_A",
                    "--candidate",
                    "SERIAL_A",
                    "--profile",
                    profile.toString(),
                ),
                root,
            )
        assertNotEquals(0, exit)
        assertTrue(Files.notExists(root.resolve("device-pair.json")))
    }

    @Test
    fun bindsCanonicalFilesWithPrivateModes() {
        val root = Files.createTempDirectory("pair-cli-")
        val profile = Files.writeString(root.resolve("profile.json"), "{}")
        assertEquals(
            0,
            HostCli.run(
                arrayOf(
                    "device-pair",
                    "bind",
                    "--donor",
                    "SERIAL_A",
                    "--candidate",
                    "SERIAL_B",
                    "--profile",
                    profile.toString(),
                ),
                root,
            ),
        )
        assertEquals(
            PosixFilePermissions.fromString("rw-------"),
            Files.getPosixFilePermissions(root.resolve("device-pair.json")),
        )
        assertEquals(
            PosixFilePermissions.fromString("rw-------"),
            Files.getPosixFilePermissions(root.resolve("device-pair.env")),
        )
        val snapshot = DevicePairSnapshot.parse(Files.readString(root.resolve("device-pair.json")))
        assertEquals("SERIAL_A", snapshot.donor.value)
        assertEquals("SERIAL_B", snapshot.candidate.value)
    }
}
