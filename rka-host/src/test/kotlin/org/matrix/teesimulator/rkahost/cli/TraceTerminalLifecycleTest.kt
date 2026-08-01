package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.LinkOption
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TraceTerminalLifecycleTest {
    @Test
    fun stopSealsReceiptMarksAndExplicitCleanupDeletesIdempotently() {
        val fixture = fixture()
        fixture.trace.beginStopping(fixture.sample)
        fixture.trace.executeTerminal(adb("shell", "getprop", "stop")) {
            HostCommandResult(0, "", "")
        }
        fixture.trace.seal()

        assertEquals(TraceLifecycleState.SEALED, TraceLifecycleStore.read(fixture.path).state)
        assertTrue(Files.exists(PersistentAdbTrace.pathFor(fixture.path)))
        assertTrue(Files.exists(fixture.path))
        val receipt = receipt(fixture)
        fixture.trace.markReceipted(receipt)
        assertEquals(TraceLifecycleState.RECEIPTED, TraceLifecycleStore.read(fixture.path).state)

        PersistentAdbTrace.cleanupAfterReceipt(fixture.path, fixture.baseline, fixture.runtime)
        PersistentAdbTrace.cleanupAfterReceipt(fixture.path, null, fixture.runtime)

        assertFalse(Files.exists(fixture.path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(
            Files.exists(PersistentAdbTrace.pathFor(fixture.path), LinkOption.NOFOLLOW_LINKS)
        )
        assertFalse(
            Files.exists(TraceLifecycleStore.pathFor(fixture.path), LinkOption.NOFOLLOW_LINKS)
        )
    }

    @Test
    fun receiptBeforeSealCleanupBeforeReceiptPostSealAppendAndDoubleReceiptAreRejected() {
        val fixture = fixture()
        assertThrows(HostCliException::class.java) { fixture.trace.snapshotForReceipt() }
        assertThrows(HostCliException::class.java) {
            PersistentAdbTrace.cleanupAfterReceipt(fixture.path, fixture.baseline, fixture.runtime)
        }
        fixture.trace.beginStopping(fixture.sample)
        fixture.trace.seal()
        assertThrows(HostCliException::class.java) {
            fixture.trace.execute(adb("shell", "getprop")) { HostCommandResult(0, "", "") }
        }
        val receipt = receipt(fixture)
        fixture.trace.markReceipted(receipt)
        val duplicate =
            assertThrows(HostCliException::class.java) {
                fixture.trace.markReceipted(receipt.replace("source_sha", "source_hash"))
            }
        assertEquals("COMMAND_TRACE_ALREADY_RECEIPTED", duplicate.message)
    }

    @Test
    fun terminalAtomicMoveCrashRecoversWithoutCommandReplay() {
        val fixture = fixture()
        TraceIo.faultForTests = { point ->
            if (point == TraceIoPoint.BEFORE_PARENT_FSYNC) throw java.io.IOException("parent-fsync")
        }
        try {
            assertThrows(HostCliException::class.java) {
                fixture.trace.beginStopping(fixture.sample)
            }
        } finally {
            TraceIo.resetTestSeams()
        }

        assertEquals(TraceLifecycleState.STOPPING, TraceLifecycleStore.read(fixture.path).state)
        val retry =
            assertThrows(HostCliException::class.java) {
                fixture.trace.beginStopping(fixture.sample)
            }
        assertEquals("COMMAND_TRACE_STATE_INVALID", retry.message)
    }

    private fun fixture(): Fixture {
        val runtime = Files.createTempDirectory("trace-terminal-")
        val path = runtime.resolve("baseline.json")
        val trace = PersistentAdbTrace.create(path, binding, "sentinel", "nonce")
        val initial = trace.validateClean().binding
        val baseline =
            SentinelBaseline(
                "sentinel",
                "nonce",
                binding,
                "donor-boot",
                "candidate-boot",
                1,
                1,
                commandTraceGenesisSha256 = initial.genesisSha256,
                commandTraceSessionId = initial.sessionId,
                commandTraceInitialHeadSha256 = initial.headSha256,
            )
        BaselineStore.create(path, baseline)
        TraceContextStore.write(runtime, path, baseline)
        trace.execute(adb("shell", "getprop", "active")) { HostCommandResult(0, "", "") }
        return Fixture(
            runtime,
            path,
            baseline,
            trace,
            SentinelSample(
                "sentinel",
                "donor-boot",
                "candidate-boot",
                2,
                2,
                SentinelPhase.ROOT_AUTHORITATIVE,
            ),
        )
    }

    private fun receipt(fixture: Fixture): String =
        PhysicalReceipt.create(
            fixture.baseline,
            "donor-boot",
            "candidate-boot",
            2,
            2,
            "a".repeat(40),
            "b".repeat(64),
            fixture.trace.snapshotForReceipt(),
        )

    private fun adb(vararg arguments: String): List<String> =
        listOf("adb", "-s", "DONOR_SERIAL") + arguments

    private data class Fixture(
        val runtime: java.nio.file.Path,
        val path: java.nio.file.Path,
        val baseline: SentinelBaseline,
        val trace: PersistentAdbTrace,
        val sample: SentinelSample,
    )

    private companion object {
        val binding =
            PairBinding(
                "a".repeat(64),
                Hashes.sha256("DONOR_SERIAL".toByteArray()),
                Hashes.sha256("CANDIDATE_SERIAL".toByteArray()),
                "d".repeat(64),
            )
    }
}
