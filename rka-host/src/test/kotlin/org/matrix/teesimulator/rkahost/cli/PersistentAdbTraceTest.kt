package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistentAdbTraceTest {
    private val binding =
        PairBinding(
            "a".repeat(64),
            Hashes.sha256("DONOR_SERIAL".toByteArray()),
            Hashes.sha256("CANDIDATE_SERIAL".toByteArray()),
            "d".repeat(64),
        )

    @Test
    fun separateOpenersPreserveOrderedAttemptsResultsAndControlledFailure() {
        val fixture = fixture()
        fixture.trace.execute(adb("shell", "getprop", "ro.build.version.release")) {
            HostCommandResult(0, "ok", "")
        }
        PersistentAdbTrace.open(fixture.path, fixture.baseline).execute(
            adb("push", "/tmp/release.zip", "/data/local/tmp/release.zip")
        ) {
            HostCommandResult(17, "", "controlled")
        }
        val final = PersistentAdbTrace.open(fixture.path, fixture.baseline).validateClean()
        val text = final.canonical.toString(Charsets.UTF_8)

        assertEquals(4, final.binding.eventCount)
        assertEquals("CLEAN", final.verdict)
        assertTrue(text.contains("EXIT_NONZERO|17|"))
        assertFalse(text.contains("DONOR_SERIAL"))
        assertFalse(text.contains("release-payload"))
    }

    @Test
    fun truncationOrphanReorderDuplicateReplayAndCrossBindingFailClosed() {
        val fixture = fixture()
        fixture.trace.execute(adb("shell", "cat", "/proc/uptime")) { HostCommandResult(0, "", "") }
        val journalPath = PersistentAdbTrace.pathFor(fixture.path)
        val original = Files.readString(journalPath)
        val lines = original.lines().filter(String::isNotEmpty)
        val mutations =
            listOf(
                original.dropLast(2),
                lines.dropLast(1).joinToString("\n", postfix = "\n"),
                listOf(lines[0], lines[2], lines[1]).joinToString("\n", postfix = "\n"),
                (lines + lines.last()).joinToString("\n", postfix = "\n"),
            )
        mutations.forEach { mutation ->
            Files.writeString(journalPath, mutation)
            assertThrows(HostCliException::class.java) {
                PersistentAdbTrace.open(fixture.path, fixture.baseline)
            }
        }
        Files.writeString(journalPath, original)
        assertThrows(HostCliException::class.java) {
            PersistentAdbTrace.open(fixture.path, fixture.baseline.copy(nonce = "other"))
        }
        assertThrows(HostCliException::class.java) {
            PersistentAdbTrace.open(
                fixture.path,
                fixture.baseline.copy(binding = binding.copy(pairHash = "e".repeat(64))),
            )
        }
    }

    @Test
    fun forbiddenTimeoutAndSpawnFailureAreTerminalAndCannotClaimClean() {
        listOf("forbidden", "timeout", "spawn").forEach { kind ->
            val fixture = fixture()
            when (kind) {
                "forbidden" ->
                    assertThrows(HostCliException::class.java) {
                        fixture.trace.execute(adb("shell", "reboot")) {
                            HostCommandResult(0, "", "")
                        }
                    }
                "timeout" ->
                    assertThrows(HostCliException::class.java) {
                        fixture.trace.execute(adb("shell", "getprop")) {
                            throw HostCliException("ADB_TIMEOUT")
                        }
                    }
                "spawn" ->
                    assertThrows(HostCliException::class.java) {
                        fixture.trace.execute(adb("shell", "getprop")) {
                            throw HostCliException("ADB_START_FAILED")
                        }
                    }
            }
            assertEquals("DIRTY", fixture.trace.validateClean().verdict)
            assertThrows(HostCliException::class.java) {
                PhysicalReceipt.create(
                    fixture.baseline,
                    "donor-boot",
                    "candidate-boot",
                    2,
                    2,
                    "a".repeat(40),
                    "f".repeat(64),
                    fixture.trace.snapshotForReceipt(),
                )
            }
        }
    }

    @Test
    fun concurrentProcessesSerializeWithoutSkippedOrDuplicateSequence() {
        val fixture = fixture()
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val futures =
            List(2) { index ->
                pool.submit {
                    val trace = PersistentAdbTrace.open(fixture.path, fixture.baseline)
                    ready.countDown()
                    start.await()
                    trace.execute(adb("shell", "getprop", "property$index")) {
                        HostCommandResult(0, "", "")
                    }
                }
            }
        assertTrue(ready.await(5, TimeUnit.SECONDS))
        start.countDown()
        futures.forEach { it.get(5, TimeUnit.SECONDS) }
        pool.shutdownNow()
        assertEquals(4, fixture.trace.validateClean().binding.eventCount)
    }

    @Test
    fun wrongModeAndSymlinkAreRejected() {
        val fixture = fixture()
        val journal = PersistentAdbTrace.pathFor(fixture.path)
        Files.setPosixFilePermissions(journal, PosixFilePermissions.fromString("rw-r-----"))
        assertThrows(HostCliException::class.java) { fixture.trace.validateClean() }
    }

    private fun fixture(): Fixture {
        val path = Files.createTempDirectory("adb-trace-").resolve("baseline.json")
        val trace = PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
        val state = trace.validateClean().binding
        val baseline =
            SentinelBaseline(
                "sentinel",
                "nonce",
                binding,
                "donor-boot",
                "candidate-boot",
                1,
                1,
                commandTraceGenesisSha256 = state.genesisSha256,
                commandTraceSessionId = state.sessionId,
                commandTraceInitialHeadSha256 = state.headSha256,
            )
        return Fixture(path, baseline, trace)
    }

    private fun adb(vararg arguments: String): List<String> =
        listOf("adb", "-s", "DONOR_SERIAL") + arguments

    private data class Fixture(
        val path: java.nio.file.Path,
        val baseline: SentinelBaseline,
        val trace: PersistentAdbTrace,
    )
}
