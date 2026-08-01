package org.matrix.teesimulator.rkahost.cli

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.time.Duration
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.matrix.teesimulator.rkahost.evidence.NoRebootSentinel

internal const val RKA_CONTROL_PATH = "/data/adb/modules/tricky_store/rka-control.sh"
internal const val RKA_RELEASE_REMOTE = "/data/local/tmp/teesimulator-rka.zip"

data class HostCommandResult(val exitCode: Int, val stdout: String, val stderr: String)

fun interface HostCommandRunner {
    fun run(argv: List<String>): HostCommandResult

    fun runRoot(serial: BoundSerial, script: String, arguments: List<String>): HostCommandResult =
        run(listOf("adb", "-s", serial.value, "shell", "su", "0", "sh") + arguments)

    fun runRoot(
        serial: BoundSerial,
        script: String,
        arguments: List<String>,
        privateInput: RootPrivateInput,
    ): HostCommandResult {
        if (privateInput != RootPrivateInput.EMPTY)
            throw HostCliException("ROOT_PRIVATE_INPUT_UNSUPPORTED")
        return runRoot(serial, script, arguments)
    }
}

class RootPrivateInput private constructor(internal val canonical: String) {
    override fun equals(other: Any?): Boolean =
        other is RootPrivateInput && canonical == other.canonical

    override fun hashCode(): Int = canonical.hashCode()

    companion object {
        val EMPTY = RootPrivateInput("")

        fun parse(lines: List<String>): RootPrivateInput {
            require(lines.size <= MAX_LINES && lines.distinct().size == lines.size) {
                "ROOT_PRIVATE_INPUT_INVALID"
            }
            require(lines.all { it.matches(Regex("[A-Za-z0-9_.-]{1,128}")) }) {
                "ROOT_PRIVATE_INPUT_INVALID"
            }
            val canonical =
                lines.sorted().joinToString("\n", postfix = if (lines.isEmpty()) "" else "\n")
            require(canonical.toByteArray().size <= MAX_BYTES) { "ROOT_PRIVATE_INPUT_INVALID" }
            return if (canonical.isEmpty()) EMPTY else RootPrivateInput(canonical)
        }

        private const val MAX_LINES = 16
        private const val MAX_BYTES = 2_048
    }
}

internal data class SentinelLimits(
    val maximumSamples: Int,
    val maximumDuration: Duration,
    val maximumFrameBytes: Int,
    val maximumTotalFrameBytes: Int,
    val maximumStateFiles: Int,
    val maximumFieldBytes: Int,
) {
    init {
        require(maximumSamples == NoRebootSentinel.MAXIMUM_SAMPLES)
        require(
            maximumDuration == Duration.ofMillis(maximumSamples * NoRebootSentinel.MAX_GAP_MILLIS)
        )
        require(maximumTotalFrameBytes == maximumSamples * maximumFrameBytes + STATE_OVERHEAD_BYTES)
        require(maximumStateFiles == maximumSamples + STATE_OVERHEAD_FILES)
    }

    fun arguments(): List<String> =
        listOf(
            maximumSamples.toString(),
            maximumDuration.toSeconds().toString(),
            maximumFrameBytes.toString(),
            maximumTotalFrameBytes.toString(),
            maximumStateFiles.toString(),
            maximumFieldBytes.toString(),
        )

    companion object {
        val PRE_INSTALL =
            SentinelLimits(
                maximumSamples = NoRebootSentinel.MAXIMUM_SAMPLES,
                maximumDuration =
                    Duration.ofMillis(
                        NoRebootSentinel.MAXIMUM_SAMPLES * NoRebootSentinel.MAX_GAP_MILLIS
                    ),
                maximumFrameBytes = 1_024,
                maximumTotalFrameBytes =
                    NoRebootSentinel.MAXIMUM_SAMPLES * 1_024 + STATE_OVERHEAD_BYTES,
                maximumStateFiles = NoRebootSentinel.MAXIMUM_SAMPLES + STATE_OVERHEAD_FILES,
                maximumFieldBytes = 256,
            )

        private const val STATE_OVERHEAD_FILES = 6
        private const val STATE_OVERHEAD_BYTES = 8_192
    }
}

class ProcessHostCommandRunner(
    private val executable: String = "adb",
    private val inheritedStdin: ByteArray? = null,
) : HostCommandRunner {
    override fun run(argv: List<String>): HostCommandResult = execute(argv, inheritedStdin)

    override fun runRoot(
        serial: BoundSerial,
        script: String,
        arguments: List<String>,
    ): HostCommandResult = runRoot(serial, script, arguments, RootPrivateInput.EMPTY)

    override fun runRoot(
        serial: BoundSerial,
        script: String,
        arguments: List<String>,
        privateInput: RootPrivateInput,
    ): HostCommandResult {
        if (
            !script.endsWith('\n') ||
                arguments.any { !it.matches(Regex("[A-Za-z0-9_./:-]{1,1024}")) } ||
                script.contains(ROOT_SCRIPT_DELIMITER) ||
                script.contains(ROOT_PRIVATE_INPUT_DELIMITER)
        ) {
            throw HostCliException("ROOT_INPUT_INVALID")
        }
        val payload = buildString {
            append("set -eu\nset -f\numask 077\n")
            append("rka_script=\$(mktemp /data/local/tmp/rka-host-root.XXXXXX)\n")
            append("trap 'rm -f \"\$rka_script\"' 0 HUP INT TERM\n")
            append("cat > \"\$rka_script\" <<'").append(ROOT_SCRIPT_DELIMITER).append("'\n")
            append("set --")
            arguments.forEach { append(' ').append(it) }
            append('\n').append(script)
            append(ROOT_SCRIPT_DELIMITER).append('\n')
            append("chmod 600 \"\$rka_script\"\n")
            append("[ -f \"\$rka_script\" ] && [ ! -L \"\$rka_script\" ]\n")
            append("[ \"\$(stat -c %u \"\$rka_script\")\" = \"\$(id -u)\" ]\n")
            append("[ \"\$(stat -c %a \"\$rka_script\")\" = 600 ]\n")
            append("status=0\n")
            append("sh \"\$rka_script\" </dev/null 3<<'")
                .append(ROOT_PRIVATE_INPUT_DELIMITER)
                .append("' || status=\$?\n")
            append(privateInput.canonical)
            append(ROOT_PRIVATE_INPUT_DELIMITER).append('\n')
            append("rm -f \"\$rka_script\"\nrka_script=\n")
            append("trap - 0 HUP INT TERM\nexit \"\$status\"\n")
        }
        if (payload.toByteArray(Charsets.UTF_8).size > ROOT_INPUT_MAX_BYTES) {
            throw HostCliException("ROOT_INPUT_INVALID")
        }
        return execute(
            listOf("adb", "-s", serial.value, "shell", "su", "0", "sh"),
            payload.toByteArray(Charsets.UTF_8),
        )
    }

    private fun execute(argv: List<String>, stdin: ByteArray?): HostCommandResult {
        val liveArgv = listOf(executable) + argv.drop(1)
        val process =
            try {
                ProcessBuilder(liveArgv).start()
            } catch (_: Exception) {
                throw HostCliException("ADB_START_FAILED")
            }
        val executor =
            Executors.newFixedThreadPool(3) { task ->
                Thread(task, "rka-host-process-io").apply { isDaemon = true }
            }
        val stdout = executor.submit<CapturedOutput> { capture(process.inputStream) }
        val stderr = executor.submit<CapturedOutput> { capture(process.errorStream) }
        val input =
            executor.submit<Unit> {
                process.outputStream.use { output -> if (stdin != null) output.write(stdin) }
            }
        val deadline = System.nanoTime() + COMMAND_TIMEOUT.toNanos()
        try {
            if (!process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS)) {
                throw HostCliException("ADB_TIMEOUT")
            }
            awaitInput(input, deadline)
            val capturedStdout = awaitOutput(stdout, deadline)
            val capturedStderr = awaitOutput(stderr, deadline)
            if (capturedStdout.truncated || capturedStderr.truncated) {
                return HostCommandResult(
                    OUTPUT_LIMIT_EXIT_CODE,
                    capturedStdout.text,
                    capturedStderr.text + OUTPUT_TRUNCATED_MARKER,
                )
            }
            return HostCommandResult(process.exitValue(), capturedStdout.text, capturedStderr.text)
        } catch (failure: HostCliException) {
            process.destroyForcibly()
            throw failure
        } finally {
            if (process.isAlive) process.destroyForcibly()
            process.outputStream.close()
            process.inputStream.close()
            process.errorStream.close()
            input.cancel(true)
            stdout.cancel(true)
            stderr.cancel(true)
            executor.shutdownNow()
        }
    }

    private fun capture(input: InputStream): CapturedOutput {
        val captured = ByteArrayOutputStream()
        val buffer = ByteArray(8_192)
        var truncated = false
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            val retained = minOf(count, OUTPUT_MAX_BYTES - captured.size())
            if (retained > 0) captured.write(buffer, 0, retained)
            if (retained < count) truncated = true
        }
        return CapturedOutput(captured.toString(Charsets.UTF_8), truncated)
    }

    private fun awaitInput(input: Future<Unit>, deadline: Long) {
        try {
            input.get(remaining(deadline), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            throw HostCliException("ADB_TIMEOUT")
        } catch (_: ExecutionException) {
            throw HostCliException("ADB_STDIN_FAILED")
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw HostCliException("ADB_TIMEOUT")
        }
    }

    private fun awaitOutput(output: Future<CapturedOutput>, deadline: Long): CapturedOutput =
        try {
            output.get(remaining(deadline), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            throw HostCliException("ADB_TIMEOUT")
        } catch (_: ExecutionException) {
            throw HostCliException("ADB_OUTPUT_FAILED")
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw HostCliException("ADB_TIMEOUT")
        }

    private fun remaining(deadline: Long): Long = maxOf(1, deadline - System.nanoTime())

    private data class CapturedOutput(val text: String, val truncated: Boolean)

    private companion object {
        val COMMAND_TIMEOUT: Duration = Duration.ofSeconds(30)
        const val ROOT_INPUT_MAX_BYTES = 65_536
        const val OUTPUT_MAX_BYTES = 1_048_576
        const val OUTPUT_LIMIT_EXIT_CODE = 74
        const val OUTPUT_TRUNCATED_MARKER = "RKA_ADB_OUTPUT_TRUNCATED\n"
        const val ROOT_SCRIPT_DELIMITER = "RKA_ROOT_SCRIPT_89C4B517"
        const val ROOT_PRIVATE_INPUT_DELIMITER = "RKA_PRIVATE_INPUT_V1"
    }
}

data class SentinelSample(
    val sentinelId: String,
    val donorBootId: String,
    val candidateBootId: String,
    val donorMillis: Long,
    val candidateMillis: Long,
    val phase: SentinelPhase = SentinelPhase.ROOT_AUTHORITATIVE,
)

enum class SentinelPhase {
    ROOT_AUTHORITATIVE,
    INSTALLED_OBSERVED,
}

enum class SentinelScope {
    PAIR,
    DONOR,
}
