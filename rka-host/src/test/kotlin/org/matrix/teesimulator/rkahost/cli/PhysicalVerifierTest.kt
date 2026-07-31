package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhysicalVerifierTest {
    private val baseline =
        SentinelBaseline("sentinel", "n", "pair", "donor-boot", "candidate-boot", 100, 100)

    @Test
    fun rejectsProbeOnlyReceipt() {
        val manifest =
            """{"artifact_sha256":"${"a".repeat(64)}","command_trace_sha256":"${"b".repeat(64)}","contains_reboot":false,"kind":"task5-probe","nonce":"n","sample_chain_sha256":"${"c".repeat(64)}","sample_count":2,"source_sha":"${"d".repeat(40)}","transport":"DIRECT","version":1}
"""
        val error =
            assertThrows(HostCliException::class.java) {
                PhysicalReceipt.verify(manifest, baseline, "d".repeat(40), "a".repeat(64), "n")
            }
        assertEquals("PROBE_ONLY_EVIDENCE", error.message)
    }

    @Test
    fun rejectsRebootTraceAndDiagnosticProduction() {
        val base =
            """{"artifact_sha256":"${"a".repeat(64)}","command_trace_sha256":"${"b".repeat(64)}","contains_reboot":true,"kind":"physical-release","nonce":"n","sample_chain_sha256":"${"c".repeat(64)}","sample_count":2,"source_sha":"${"d".repeat(40)}","transport":"DIAGNOSTIC_USB","version":1}
"""
        assertThrows(HostCliException::class.java) {
            PhysicalReceipt.verify(base, baseline, "d".repeat(40), "a".repeat(64), "n")
        }
    }

    @Test
    fun verifierReadsExactArtifactHash() {
        val artifact = Files.createTempFile("artifact-", ".zip")
        Files.writeString(artifact, "release")
        val digest = Hashes.sha256(Files.readAllBytes(artifact))
        val manifest =
            PhysicalReceipt.create(
                baseline,
                "donor-boot",
                "candidate-boot",
                200,
                200,
                "d".repeat(40),
                digest,
                listOf(listOf("adb", "-s", "DONOR_A", "shell", "getprop")),
            )
        assertEquals(
            digest,
            PhysicalReceipt.verify(manifest, baseline, "d".repeat(40), digest, "n"),
        )
    }
}
