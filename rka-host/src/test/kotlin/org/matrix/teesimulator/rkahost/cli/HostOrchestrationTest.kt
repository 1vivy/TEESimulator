package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HostOrchestrationTest {
    private val pair =
        DevicePairSnapshot(
            BoundSerial.parse("DONOR_A"),
            BoundSerial.parse("CANDIDATE_B"),
            "a".repeat(64),
        )

    @Test
    fun serialsAndSentinelBaselinesCoverEveryCandidate() {
        // Given
        val multiCandidatePair =
            DevicePairSnapshot(
                BoundSerial.parse("DONOR_A"),
                listOf(
                    DevicePairCandidate(BoundSerial.parse("CANDIDATE_B"), "a".repeat(64)),
                    DevicePairCandidate(BoundSerial.parse("CANDIDATE_C"), "b".repeat(64)),
                ),
                2,
            )
        val path = Files.createTempDirectory("sentinel-multi-candidate-").resolve("baseline.json")
        val runner = RecordingRunner()

        // When
        val baseline = HostOrchestrator(multiCandidatePair, runner).sentinelStart(path, "nonce-A")

        // Then
        assertEquals(
            setOf("DONOR_A", "CANDIDATE_B", "CANDIDATE_C"),
            runner.calls.mapNotNull { it.getOrNull(2) }.toSet(),
        )
        assertEquals(setOf("CANDIDATE_B", "CANDIDATE_C"), baseline.candidateBootIds.keys)
        assertEquals(setOf("CANDIDATE_B", "CANDIDATE_C"), baseline.candidateStartMillisBySerial.keys)
    }

    @Test
    fun everyAdvertisedCommandUsesRoleBoundNoRebootArgv() {
        val runner = RecordingRunner()
        val host = HostOrchestrator(pair, runner)

        host.profilePair()
        host.deployNoReboot("/tmp/release.zip")
        host.snapshot("capability")
        host.snapshot("config")
        host.lifecycle("status")
        host.lifecycle("start")
        host.lifecycle("stop")
        host.cleanup()

        assertTrue(runner.calls.all { it.take(2) == listOf("adb", "-s") })
        assertTrue(runner.calls.all { it[2] in setOf("DONOR_A", "CANDIDATE_B") })
        assertFalse(runner.calls.flatten().any { it == "reboot" || it == "killall" })
        assertTrue(runner.calls.any { "deploy-no-reboot" in it })
    }

    @Test
    fun sentinelBaselineIsCreateOnceAndBootBound() {
        val root = Files.createTempDirectory("sentinel-baseline-")
        val path = root.resolve("baseline.json")
        val runner = RecordingRunner()
        val host = HostOrchestrator(pair, runner)

        host.sentinelStart(path, "nonce-A")
        assertTrue(Files.exists(path))
        val error =
            org.junit.Assert.assertThrows(HostCliException::class.java) {
                host.sentinelStart(path, "nonce-A")
            }
        assertEquals("BASELINE_ALREADY_EXISTS", error.message)
    }

    @Test
    fun oldBaselineRejectsDifferentCurrentRolePair() {
        val path = Files.createTempDirectory("sentinel-rebind-").resolve("baseline.json")
        val runner = RecordingRunner()
        HostOrchestrator(pair, runner).sentinelStart(path, "nonce-A")
        val rebound =
            DevicePairSnapshot(
                BoundSerial.parse("DONOR_C"),
                BoundSerial.parse("CANDIDATE_D"),
                "b".repeat(64),
            )

        val failure =
            assertThrows(HostCliException::class.java) {
                HostOrchestrator(rebound, runner).sentinelSample(path)
            }

        assertEquals("PAIR_BINDING_MISMATCH", failure.message)
    }

    @Test
    fun firstSentinelStartFailureLeavesNoReadyBaselineAndCleansUp() {
        assertFailedStartLeavesNoBaseline(1)
    }

    @Test
    fun secondSentinelStartFailureLeavesNoReadyBaselineAndCleansUp() {
        assertFailedStartLeavesNoBaseline(2)
    }

    @Test
    fun donorScopeRetainsPairBindingWithoutAddressingCandidate() {
        val path = Files.createTempDirectory("sentinel-donor-").resolve("baseline.json")
        val runner = RecordingRunner()
        val host = HostOrchestrator(pair, runner)

        val baseline = host.sentinelStart(path, "nonce-A", SentinelScope.DONOR)
        host.sentinelStop(path)

        assertEquals(SentinelScope.DONOR, baseline.scope)
        assertEquals(PairBinding.from(pair), baseline.binding)
        assertFalse(runner.calls.any { it.getOrNull(2) == "CANDIDATE_B" })
        assertTrue(Files.exists(path))
        assertTrue(
            Files.readString(path.resolveSibling(".${path.fileName}.trace-state-v2"))
                .startsWith("SEALED|")
        )
    }

    @Test
    fun pendingStartWithoutPersistentTraceFailsClosedWithoutRetry() {
        val path = Files.createTempDirectory("sentinel-pending-").resolve("baseline.json")
        val pending =
            SentinelBaseline(
                "old-sentinel",
                "old-nonce",
                PairBinding.from(pair),
                "donor-boot",
                "candidate-boot",
                100,
                100,
            )
        BaselineStore.createPending(path, pending)
        val runner = RecordingRunner()

        assertThrows(HostCliException::class.java) { BaselineStore.read(path) }
        val error =
            assertThrows(HostCliException::class.java) {
                HostOrchestrator(pair, runner).sentinelStart(path, "nonce-A")
            }

        assertEquals("COMMAND_TRACE_PATH_UNSAFE", error.message)
        assertTrue(BaselineStore.hasPending(path))
        assertTrue(runner.calls.isEmpty())
    }

    @Test
    fun readyLinkWithPendingMarkerFinalizesWithoutStoppingSentinel() {
        val path = Files.createTempDirectory("sentinel-commit-recovery-").resolve("baseline.json")
        val baseline =
            SentinelBaseline(
                "sentinel",
                "nonce-A",
                PairBinding.from(pair),
                "donor-boot",
                "candidate-boot",
                100,
                100,
            )
        BaselineStore.createPending(path, baseline)
        Files.createLink(path, path.resolveSibling(".${path.fileName}.pending"))
        val runner = RecordingRunner()

        val failure =
            assertThrows(HostCliException::class.java) {
                HostOrchestrator(pair, runner).sentinelStart(path, "nonce-A")
            }

        assertEquals("BASELINE_ALREADY_EXISTS", failure.message)
        assertFalse(BaselineStore.hasPending(path))
        assertFalse(runner.calls.any { "cleanup" in it })
    }

    @Test
    fun interruptedSamplingAndAssertionPreserveBaselineForDeterministicResume() {
        val path = Files.createTempDirectory("sentinel-resume-").resolve("baseline.json")
        val runner = RecordingRunner(failures = mutableMapOf("sample" to 1, "assert-live" to 1))
        val host = HostOrchestrator(pair, runner)
        host.sentinelStart(path, "nonce-A")

        assertThrows(HostCliException::class.java) { host.sentinelSample(path) }
        assertTrue(Files.exists(path))
        host.sentinelSample(path)
        assertThrows(HostCliException::class.java) { host.sentinelAssertLive(path) }
        assertTrue(Files.exists(path))
        host.sentinelAssertLive(path)
        host.sentinelStop(path)

        assertTrue(Files.exists(path))
        assertTrue(
            Files.readString(path.resolveSibling(".${path.fileName}.trace-state-v2"))
                .startsWith("SEALED|")
        )
    }

    @Test
    fun interruptedStopIsIdempotentlyRetriedWithoutDroppingBaseline() {
        val path = Files.createTempDirectory("sentinel-stop-resume-").resolve("baseline.json")
        val runner = RecordingRunner(failures = mutableMapOf("stop" to 1))
        val host = HostOrchestrator(pair, runner)
        host.sentinelStart(path, "nonce-A")

        assertThrows(HostCliException::class.java) { host.sentinelStop(path) }
        assertTrue(Files.exists(path))
        val retry = assertThrows(HostCliException::class.java) { host.sentinelStop(path) }

        assertEquals("COMMAND_TRACE_TERMINAL_INCOMPLETE", retry.message)
        assertTrue(Files.exists(path))
    }

    @Test
    fun misleadingSuccessAndOversizedSampleCountAreRejected() {
        val misleading = Files.createTempDirectory("sentinel-misleading-").resolve("baseline.json")
        val misleadingRunner = RecordingRunner(misleadingActions = setOf("start"))
        assertThrows(HostCliException::class.java) {
            HostOrchestrator(pair, misleadingRunner).sentinelStart(misleading, "nonce-A")
        }
        assertFalse(Files.exists(misleading))

        val oversized = Files.createTempDirectory("sentinel-count-").resolve("baseline.json")
        val oversizedRunner = RecordingRunner(sampleCounts = mapOf("assert-live" to 1_025))
        val host = HostOrchestrator(pair, oversizedRunner)
        host.sentinelStart(oversized, "nonce-A")
        assertThrows(HostCliException::class.java) { host.sentinelAssertLive(oversized) }
    }

    private fun assertFailedStartLeavesNoBaseline(failingStart: Int) {
        val path = Files.createTempDirectory("sentinel-failure-").resolve("baseline.json")
        val runner = RecordingRunner(failingStart)

        assertThrows(HostCliException::class.java) {
            HostOrchestrator(pair, runner).sentinelStart(path, "nonce-A")
        }

        assertFalse(Files.exists(path))
        assertFalse(BaselineStore.hasPending(path))
        assertTrue(runner.calls.any { "stop" in it })
    }

    private class RecordingRunner(
        private val failingStart: Int? = null,
        private val failures: MutableMap<String, Int> = mutableMapOf(),
        private val misleadingActions: Set<String> = emptySet(),
        private val sampleCounts: Map<String, Int> = emptyMap(),
    ) : HostCommandRunner {
        val calls = mutableListOf<List<String>>()
        private var starts = 0
        private var uptimeSamples = 0

        override fun run(argv: List<String>): HostCommandResult {
            calls += argv
            if ("sentinel" in argv && "start" in argv && ++starts == failingStart) {
                return HostCommandResult(1, "", "injected")
            }
            val output =
                when (argv.last()) {
                    "/proc/sys/kernel/random/boot_id" ->
                        if (argv[2] == "DONOR_A") "donor-boot\n" else "candidate-boot\n"
                    "/proc/uptime" -> "123.${45 + uptimeSamples++} 1.0\n"
                    else ->
                        if (
                            "sentinel" in argv &&
                                argv.any { it in setOf("start", "sample", "finish", "verify") }
                        ) {
                            val action =
                                argv.first { it in setOf("start", "sample", "finish", "verify") }
                            val id = argv[argv.indexOf("--id") + 1]
                            val nonce = argv[argv.indexOf("--nonce") + 1]
                            "sentinel_id=$id nonce=$nonce action=$action\n"
                        } else {
                            "ok\n"
                        }
                }
            return HostCommandResult(0, output, "")
        }

        override fun runRoot(
            serial: BoundSerial,
            script: String,
            arguments: List<String>,
            privateInput: RootPrivateInput,
        ): HostCommandResult {
            calls += listOf("adb", "-s", serial.value, "shell", "su", "0", "sh") + arguments
            val action = arguments[0]
            if (action == "start" && ++starts == failingStart) {
                return HostCommandResult(1, "", "injected")
            }
            val remainingFailures = failures[action] ?: 0
            if (remainingFailures > 0) {
                failures[action] = remainingFailures - 1
                return HostCommandResult(1, "success", "injected")
            }
            if (action in misleadingActions) return HostCommandResult(0, "success", "")
            val phase = if (action == "stop") "STOPPED" else "ROOT_AUTHORITATIVE"
            return HostCommandResult(
                0,
                "sentinel_id=${arguments[1]} action=$action phase=$phase samples=${sampleCounts[action] ?: if (action == "start") 1 else 2}\n",
                "",
            )
        }
    }
}
