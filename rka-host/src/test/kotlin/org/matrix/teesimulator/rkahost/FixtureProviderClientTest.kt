package org.matrix.teesimulator.rkahost

import java.time.Duration
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FixtureProviderClientTest {
    private val nonce = ByteArray(16) { (it + 1).toByte() }
    private val donor = DeviceSerial.of(DeviceRole.DONOR, "donor-1")
    private val candidate = DeviceSerial.of(DeviceRole.CANDIDATE, "candidate:5555")

    @Test
    fun writeReadDelete() {
        val runner =
            TranscriptRunner(
                AdbResult(0, ByteArray(0)),
                AdbResult(
                    0,
                    FixtureResponse.encode(nonce, byteArrayOf(0x41, 0, 0x42, 0xff.toByte())),
                ),
            )
        val relay = UsbHostRelayTransport(donor, candidate, runner, { nonce })

        assertArrayEquals(
            byteArrayOf(0x41, 0, 0x42, 0xff.toByte()),
            relay.exchange(byteArrayOf(0x41, 0, 0x42, 0xff.toByte())),
        )
        assertEquals(listOf("write", "read", "delete"), runner.commands.map { it[5] })
        assertEquals(
            listOf("adb", "-s", "donor-1", "shell", "content", "write"),
            runner.commands.first().take(6),
        )
        assertTrue(runner.commands.all { it[7].startsWith(FixtureProviderClient.AUTHORITY) })
        assertArrayEquals(byteArrayOf(0x41, 0, 0x42, 0xff.toByte()), runner.stdin.first())
    }

    @Test
    fun typedErrorStillDeletes() {
        val runner = TranscriptRunner(AdbResult(7, ByteArray(0)))
        val relay = UsbHostRelayTransport(donor, candidate, runner, { nonce })

        assertFailure<ProviderCommandException> { relay.exchange(byteArrayOf(1)) }
        assertEquals(listOf("write", "delete"), runner.commands.map { it[5] })
    }

    @Test
    fun timeoutStillDeletes() {
        val runner = TranscriptRunner(ProviderTimeoutException("ADB_TIMEOUT"))
        val relay = UsbHostRelayTransport(donor, candidate, runner, { nonce })

        assertFailure<ProviderTimeoutException> { relay.exchange(byteArrayOf(1)) }
        assertEquals(listOf("write", "delete"), runner.commands.map { it[5] })
    }

    @Test
    fun interruptionStillDeletesAndRemainsInterrupted() {
        val runner = TranscriptRunner(AdbResult(0, ByteArray(0)), InterruptedException("stop"))
        val relay = UsbHostRelayTransport(donor, candidate, runner, { nonce })

        assertFailure<InterruptedException> { relay.exchange(byteArrayOf(1)) }
        assertEquals(listOf("write", "read", "delete"), runner.commands.map { it[5] })
        assertTrue(Thread.currentThread().isInterrupted)
        Thread.interrupted()
    }

    @Test
    fun rejectsUntrustedNonceAndOversizedOutput() {
        val wrong =
            TranscriptRunner(
                AdbResult(0, ByteArray(0)),
                AdbResult(0, FixtureResponse.encode(ByteArray(16), byteArrayOf(1))),
            )
        assertFailure<ProviderProtocolException> {
            UsbHostRelayTransport(donor, candidate, wrong, { nonce }).exchange(byteArrayOf(1))
        }
        assertEquals(listOf("write", "read", "delete"), wrong.commands.map { it[5] })

        val oversized =
            TranscriptRunner(
                AdbResult(0, ByteArray(0)),
                AdbResult(0, ByteArray(FixtureProviderClient.MAX_PROVIDER_RESPONSE_BYTES + 1)),
            )
        assertFailure<ProviderOutputTooLargeException> {
            UsbHostRelayTransport(donor, candidate, oversized, { nonce }).exchange(byteArrayOf(1))
        }
        assertEquals(listOf("write", "read", "delete"), oversized.commands.map { it[5] })
    }

    @Test
    fun equalOrSwappedRolesFailBeforeAdb() {
        val runner = TranscriptRunner()
        assertFailure<IllegalArgumentException> {
            UsbHostRelayTransport(donor, DeviceSerial.of(DeviceRole.CANDIDATE, "donor-1"), runner)
        }
        assertFailure<IllegalArgumentException> {
            UsbHostRelayTransport(
                DeviceSerial.of(DeviceRole.CANDIDATE, "candidate-1"),
                candidate,
                runner,
            )
        }
        assertTrue(runner.commands.isEmpty())
    }

    @Test
    fun diagnosticKindHasNoProductionDefault() {
        val relay =
            UsbHostRelayTransport(
                donor,
                candidate,
                TranscriptRunner(),
                { nonce },
                Duration.ofSeconds(1),
            )
        assertEquals(DiagnosticTransportKind.DIAGNOSTIC_USB_RELAY, relay.kind)
    }

    private inline fun <reified T : Throwable> assertFailure(block: () -> Unit) {
        try {
            block()
        } catch (failure: Throwable) {
            assertTrue(
                "expected ${T::class.java.name}, got ${failure::class.java.name}",
                failure is T,
            )
            return
        }
        throw AssertionError("expected ${T::class.java.name}")
    }

    private class TranscriptRunner(private vararg val results: Any) : AdbCommandRunner {
        val commands = mutableListOf<List<String>>()
        val stdin = mutableListOf<ByteArray>()
        private var index = 0

        override fun run(argv: List<String>, stdin: ByteArray, timeout: Duration): AdbResult {
            commands += argv
            this.stdin += stdin
            val result = results.getOrElse(index++) { AdbResult(0, ByteArray(0)) }
            when (result) {
                is AdbResult -> return result
                is InterruptedException -> throw result
                is RuntimeException -> throw result
                else -> throw AssertionError("unexpected transcript result")
            }
        }
    }
}
