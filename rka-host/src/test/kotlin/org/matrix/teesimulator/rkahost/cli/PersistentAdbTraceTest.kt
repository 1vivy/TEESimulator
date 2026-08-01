package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
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
    fun wrongModeIsRejected() {
        val fixture = fixture()
        val journal = PersistentAdbTrace.pathFor(fixture.path)
        Files.setPosixFilePermissions(journal, PosixFilePermissions.fromString("rw-r-----"))
        assertThrows(HostCliException::class.java) { fixture.trace.validateClean() }
    }

    @Test
    fun actualSymlinkIsRejected() {
        val fixture = fixture()
        val journal = PersistentAdbTrace.pathFor(fixture.path)
        val target = journal.resolveSibling("trace-target")
        Files.move(journal, target, StandardCopyOption.ATOMIC_MOVE)
        Files.createSymbolicLink(journal, target)

        val failure = assertThrows(HostCliException::class.java) { fixture.trace.validateClean() }

        assertEquals("COMMAND_TRACE_PATH_UNSAFE", failure.message)
    }

    @Test
    fun wrongOwnerIsRejectedByInjectedIdentitySeam() {
        val fixture = fixture()
        val journal = PersistentAdbTrace.pathFor(fixture.path).toAbsolutePath()
        val trusted = Files.getOwner(java.nio.file.Path.of("/proc/self")).name
        TraceIo.ownerForTests = { path ->
            if (path.toAbsolutePath() == journal) "untrusted-owner" else trusted
        }
        try {
            val failure =
                assertThrows(HostCliException::class.java) { fixture.trace.validateClean() }
            assertEquals("COMMAND_TRACE_PATH_UNSAFE", failure.message)
        } finally {
            TraceIo.resetTestSeams()
        }
    }

    @Test
    fun atomicRenameFailureLeavesNoAmbiguousContinuation() {
        val directory = Files.createTempDirectory("trace-rename-fault-")
        val path = directory.resolve("baseline.json")
        TraceIo.faultForTests = { point ->
            if (point == TraceIoPoint.BEFORE_ATOMIC_MOVE) throw java.io.IOException("rename")
        }
        try {
            val failure =
                assertThrows(HostCliException::class.java) {
                    PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
                }
            assertEquals("COMMAND_TRACE_PERSIST_FAILED", failure.message)
            assertFalse(Files.exists(PersistentAdbTrace.pathFor(path), LinkOption.NOFOLLOW_LINKS))
            assertFalse(
                Files.exists(
                    PersistentAdbTrace.lockPathFor(PersistentAdbTrace.pathFor(path)),
                    LinkOption.NOFOLLOW_LINKS,
                )
            )
            assertTrue(
                Files.list(directory).use { entries ->
                    entries.noneMatch { it.fileName.toString().endsWith(".tmp") }
                }
            )
        } finally {
            TraceIo.resetTestSeams()
        }
    }

    @Test
    fun lockOnlyCreationCrashIsQuarantinedBeforeFreshStart() {
        val path = Files.createTempDirectory("trace-parent-fsync-fault-").resolve("baseline.json")
        var parentFsyncs = 0
        TraceIo.faultForTests = { point ->
            if (point == TraceIoPoint.BEFORE_PARENT_FSYNC && parentFsyncs++ == 0) {
                throw java.io.IOException("parent fsync")
            }
        }
        try {
            assertThrows(HostCliException::class.java) {
                PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
            }
        } finally {
            TraceIo.resetTestSeams()
        }
        assertTrue(
            Files.exists(
                PersistentAdbTrace.lockPathFor(PersistentAdbTrace.pathFor(path)),
                LinkOption.NOFOLLOW_LINKS,
            )
        )

        val recovery =
            assertThrows(HostCliException::class.java) {
                PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
            }
        assertEquals("COMMAND_TRACE_RECOVERY_REQUIRED", recovery.message)
        assertEquals(
            "CLEAN",
            PersistentAdbTrace.create(path, binding, "sentinel", "nonce").validateClean().verdict,
        )
    }

    @Test
    fun journalOnlyCreationCrashIsQuarantinedBeforeFreshStart() {
        val fixture = fixture()
        val journal = PersistentAdbTrace.pathFor(fixture.path)
        Files.delete(PersistentAdbTrace.lockPathFor(journal))
        Files.delete(TraceLifecycleStore.pathFor(fixture.path))

        val recovery =
            assertThrows(HostCliException::class.java) {
                PersistentAdbTrace.create(fixture.path, binding, "sentinel", "nonce")
            }

        assertEquals("COMMAND_TRACE_RECOVERY_REQUIRED", recovery.message)
        assertEquals(
            "CLEAN",
            PersistentAdbTrace.create(fixture.path, binding, "sentinel", "nonce")
                .validateClean()
                .verdict,
        )
    }

    @Test
    fun fsyncFailureLeavesNoAmbiguousContinuation() {
        val path = Files.createTempDirectory("trace-fsync-fault-").resolve("baseline.json")
        TraceIo.faultForTests = { point ->
            if (point == TraceIoPoint.BEFORE_FILE_FSYNC) throw java.io.IOException("fsync")
        }
        try {
            val failure =
                assertThrows(HostCliException::class.java) {
                    PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
                }
            assertEquals("COMMAND_TRACE_PERSIST_FAILED", failure.message)
            assertFalse(Files.exists(PersistentAdbTrace.pathFor(path), LinkOption.NOFOLLOW_LINKS))
        } finally {
            TraceIo.resetTestSeams()
        }
    }

    @Test
    fun lastAllowedEventAndByteBoundaryPassAndNextAreRejected() {
        PersistentAdbTrace.requireAppendCapacity(PersistentAdbTrace.maximumEventsForTests - 1, 1, 1)
        assertThrows(HostCliException::class.java) {
            PersistentAdbTrace.requireAppendCapacity(PersistentAdbTrace.maximumEventsForTests, 1, 1)
        }
        PersistentAdbTrace.requireAppendCapacity(0, PersistentAdbTrace.maximumBytesForTests - 1, 1)
        assertThrows(HostCliException::class.java) {
            PersistentAdbTrace.requireAppendCapacity(
                0,
                PersistentAdbTrace.maximumBytesForTests - 1,
                2,
            )
        }
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
