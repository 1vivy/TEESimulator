package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhysicalVerifierTest {
    private val binding =
        PairBinding(
            "a".repeat(64),
            Hashes.sha256("DONOR_A".toByteArray()),
            Hashes.sha256("CANDIDATE_A".toByteArray()),
            "d".repeat(64),
        )
    private val baseline =
        SentinelBaseline("sentinel", "n", binding, "donor-boot", "candidate-boot", 100, 100)
    private val placeholderPath = Path.of("baseline.json")

    @Test
    fun rejectsProbeOnlyReceipt() {
        val manifest =
            """{"artifact_sha256":"${"a".repeat(64)}","command_trace_sha256":"${"b".repeat(64)}","contains_reboot":false,"kind":"task5-probe","nonce":"n","sample_chain_sha256":"${"c".repeat(64)}","sample_count":2,"source_sha":"${"d".repeat(40)}","transport":"DIRECT","version":1}
"""
        val error =
            assertThrows(HostCliException::class.java) {
                PhysicalReceipt.verify(
                    manifest,
                    placeholderPath,
                    baseline,
                    binding,
                    "d".repeat(40),
                    "a".repeat(64),
                    "n",
                )
            }
        assertEquals("PROBE_ONLY_EVIDENCE", error.message)
    }

    @Test
    fun rejectsRebootTraceAndDiagnosticProduction() {
        val base =
            """{"artifact_sha256":"${"a".repeat(64)}","command_trace_sha256":"${"b".repeat(64)}","contains_reboot":true,"kind":"physical-release","nonce":"n","sample_chain_sha256":"${"c".repeat(64)}","sample_count":2,"source_sha":"${"d".repeat(40)}","transport":"DIAGNOSTIC_USB","version":1}
"""
        assertThrows(HostCliException::class.java) {
            PhysicalReceipt.verify(
                base,
                placeholderPath,
                baseline,
                binding,
                "d".repeat(40),
                "a".repeat(64),
                "n",
            )
        }
    }

    @Test
    fun verifierReadsExactArtifactHash() {
        val fixture = traceFixture()
        val artifact = Files.createTempFile("artifact-", ".zip")
        Files.writeString(artifact, "release")
        val digest = Hashes.sha256(Files.readAllBytes(artifact))
        val manifest =
            PhysicalReceipt.create(
                fixture.baseline,
                "donor-boot",
                "candidate-boot",
                200,
                200,
                "d".repeat(40),
                digest,
                fixture.trace,
            )
        assertEquals(
            digest,
            PhysicalReceipt.verify(
                manifest,
                fixture.path,
                fixture.baseline,
                binding,
                "d".repeat(40),
                digest,
                "n",
            ),
        )
    }

    private fun traceFixture(): Fixture {
        val path = Files.createTempDirectory("receipt-trace-").resolve("baseline.json")
        val journal = PersistentAdbTrace.create(path, binding, "sentinel", "n")
        val state = journal.validateClean().binding
        val tracedBaseline =
            baseline.copy(
                commandTraceGenesisSha256 = state.genesisSha256,
                commandTraceSessionId = state.sessionId,
                commandTraceInitialHeadSha256 = state.headSha256,
            )
        journal.execute(listOf("adb", "-s", "DONOR_A", "shell", "getprop")) {
            HostCommandResult(0, "", "")
        }
        return Fixture(path, tracedBaseline, journal.snapshotForReceipt())
    }

    private data class Fixture(
        val path: Path,
        val baseline: SentinelBaseline,
        val trace: ValidatedPersistentTrace,
    )
}
