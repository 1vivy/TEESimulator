package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DevicePairCliTest {
    @Test
    fun bindAcceptsTwoCandidatesAndEmitsSchemaVersionTwo() {
        // Given
        val root = Files.createTempDirectory("pair-cli-")
        val profileA = Files.writeString(root.resolve("profile-a.json"), "{\"candidate\":\"A\"}")
        val profileB = Files.writeString(root.resolve("profile-b.json"), "{\"candidate\":\"B\"}")

        // When
        val exit =
            HostCli.run(
                arrayOf(
                    "device-pair",
                    "bind",
                    "--donor",
                    "DONOR_D",
                    "--candidate",
                    "CANDIDATE_A",
                    "--profile",
                    profileA.toString(),
                    "--candidate",
                    "CANDIDATE_B",
                    "--profile",
                    profileB.toString(),
                ),
                root,
            )
        val duplicateExit =
            HostCli.run(
                arrayOf(
                    "device-pair",
                    "bind",
                    "--donor",
                    "DONOR_D",
                    "--candidate",
                    "CANDIDATE_A",
                    "--profile",
                    profileA.toString(),
                    "--candidate",
                    "CANDIDATE_A",
                    "--profile",
                    profileB.toString(),
                ),
                Files.createTempDirectory("pair-cli-duplicate-"),
            )

        // Then
        assertEquals(0, exit)
        val descriptor = Files.readString(root.resolve("device-pair.json"))
        assertTrue(descriptor.contains("\"schema_version\":2"))
        assertEquals(2, Regex("\"serial\":").findAll(descriptor).count())
        assertNotEquals(0, duplicateExit)
    }

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
