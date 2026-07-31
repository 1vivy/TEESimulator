package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        host.recoverExact("keystore2")
        host.recoverExact("rkpd")
        host.cleanup()

        assertTrue(runner.calls.all { it.take(2) == listOf("adb", "-s") })
        assertTrue(runner.calls.all { it[2] in setOf("DONOR_A", "CANDIDATE_B") })
        assertFalse(runner.calls.flatten().any { it == "reboot" || it == "killall" })
        assertTrue(runner.calls.any { "deploy-no-reboot" in it })
        assertTrue(runner.calls.any { "ctl.restart" in it && "keystore2" in it })
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

    private class RecordingRunner : HostCommandRunner {
        val calls = mutableListOf<List<String>>()

        override fun run(argv: List<String>): HostCommandResult {
            calls += argv
            val output =
                when (argv.last()) {
                    "/proc/sys/kernel/random/boot_id" ->
                        if (argv[2] == "DONOR_A") "donor-boot\n" else "candidate-boot\n"
                    "/proc/uptime" -> "123.45 1.0\n"
                    else -> "ok\n"
                }
            return HostCommandResult(0, output, "")
        }
    }
}
