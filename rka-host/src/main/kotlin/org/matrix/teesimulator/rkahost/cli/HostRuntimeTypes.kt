package org.matrix.teesimulator.rkahost.cli

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.time.Duration
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
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
    private val commandTimeout: Duration = Duration.ofSeconds(30),
) : HostCommandRunner {
    init {
        require(!commandTimeout.isZero && !commandTimeout.isNegative) { "ADB_TIMEOUT_INVALID" }
    }

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
        val remoteScript =
            "/data/local/tmp/rka-host-root.${UUID.randomUUID().toString().replace("-", "")}"
        val payload = buildString {
            append("set -eu\nset -f\numask 077\n")
            append("rka_script=").append(remoteScript).append('\n')
            append("trap 'rm -f \"\$rka_script\"' 0 HUP INT TERM\n")
            append("( set -C; : > \"\$rka_script\" ) 2>/dev/null || exit 73\n")
            append("cat > \"\$rka_script\" <<'").append(ROOT_SCRIPT_DELIMITER).append("'\n")
            append("set --")
            arguments.forEach { append(' ').append(it) }
            append('\n').append(script)
            append(ROOT_SCRIPT_DELIMITER).append('\n')
            append("chmod 600 \"\$rka_script\"\n")
            append("[ -f \"\$rka_script\" ] && [ ! -L \"\$rka_script\" ]\n")
            append("[ \"\$(stat -c %u \"\$rka_script\")\" = \"\$(id -u)\" ]\n")
            append("[ \"\$(stat -c %a \"\$rka_script\")\" = 600 ]\n")
            append("exec 9<\"\$rka_script\"\n")
            append("rm -f \"\$rka_script\"\nrka_script=\n")
            append("trap - 0 HUP INT TERM\n")
            append("status=0\n")
            append("sh /proc/self/fd/9 </dev/null 3<<'")
                .append(ROOT_PRIVATE_INPUT_DELIMITER)
                .append("' || status=\$?\n")
            append(privateInput.canonical)
            append(ROOT_PRIVATE_INPUT_DELIMITER).append('\n')
            append("exec 9<&-\nexit \"\$status\"\n")
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
            Executors.newFixedThreadPool(4) { task ->
                Thread(task, "rka-host-process-io").apply { isDaemon = true }
            }
        val processTree = TaskProcessTree(process)
        val tracking = executor.submit<Unit> { processTree.trackUntilInterrupted() }
        val stdout = executor.submit<CapturedOutput> { capture(process.inputStream) }
        val stderr = executor.submit<CapturedOutput> { capture(process.errorStream) }
        val input =
            executor.submit<Unit> {
                process.outputStream.use { output -> if (stdin != null) output.write(stdin) }
            }
        val deadline = System.nanoTime() + commandTimeout.toNanos()
        var result: HostCommandResult? = null
        var failure: HostCliException? = null
        try {
            if (!process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS)) {
                throw HostCliException("ADB_TIMEOUT")
            }
            awaitInput(input, deadline)
            val capturedStdout = awaitOutput(stdout, deadline)
            val capturedStderr = awaitOutput(stderr, deadline)
            if (capturedStdout.truncated || capturedStderr.truncated) {
                result =
                    HostCommandResult(
                        OUTPUT_LIMIT_EXIT_CODE,
                        capturedStdout.text,
                        capturedStderr.text + OUTPUT_TRUNCATED_MARKER,
                    )
            } else {
                result =
                    HostCommandResult(process.exitValue(), capturedStdout.text, capturedStderr.text)
            }
        } catch (caught: HostCliException) {
            failure = caught
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            failure = HostCliException("ADB_TIMEOUT")
        } catch (_: Exception) {
            failure = HostCliException("ADB_PROCESS_FAILED")
        } finally {
            if (failure != null) {
                runCatching { process.outputStream.close() }
                try {
                    terminateAndReap(process, processTree)
                    drainAfterTermination(stdout, stderr)
                } catch (_: Exception) {
                    failure = HostCliException("ADB_REAP_FAILED")
                }
            }
            tracking.cancel(true)
            processTree.capture()
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            input.cancel(true)
            stdout.cancel(true)
            stderr.cancel(true)
            executor.shutdownNow()
            try {
                if (!executor.awaitTermination(REAP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                    failure = HostCliException("ADB_REAP_FAILED")
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                failure = HostCliException("ADB_REAP_FAILED")
            }
        }
        failure?.let { throw it }
        return checkNotNull(result)
    }

    private fun terminateAndReap(process: Process, processTree: TaskProcessTree) {
        val deadline = System.nanoTime() + REAP_TIMEOUT.toNanos()
        while (true) {
            processTree.capture()
            if (process.isAlive) process.destroyForcibly()
            processTree.liveDescendants().forEach { it.destroyForcibly() }
            val rootReaped =
                !process.isAlive ||
                    process.waitFor(
                        minOf(remaining(deadline), REAP_POLL_NANOS),
                        TimeUnit.NANOSECONDS,
                    )
            if (rootReaped && processTree.liveDescendants().isEmpty()) return
            if (System.nanoTime() >= deadline) throw HostCliException("ADB_REAP_FAILED")
        }
    }

    private fun drainAfterTermination(
        stdout: Future<CapturedOutput>,
        stderr: Future<CapturedOutput>,
    ) {
        val deadline = System.nanoTime() + REAP_TIMEOUT.toNanos()
        stdout.get(remaining(deadline), TimeUnit.NANOSECONDS)
        stderr.get(remaining(deadline), TimeUnit.NANOSECONDS)
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

    private class TaskProcessTree(private val process: Process) {
        private val descendants = ConcurrentHashMap.newKeySet<ProcessHandle>()

        fun trackUntilInterrupted() {
            try {
                while (!Thread.currentThread().isInterrupted) {
                    capture()
                    Thread.sleep(5)
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        fun capture() {
            if (process.isAlive) process.toHandle().descendants().forEach(descendants::add)
        }

        fun liveDescendants(): List<ProcessHandle> = descendants.filter(ProcessHandle::isAlive)
    }

    private companion object {
        const val ROOT_INPUT_MAX_BYTES = 65_536
        const val OUTPUT_MAX_BYTES = 1_048_576
        const val OUTPUT_LIMIT_EXIT_CODE = 74
        const val OUTPUT_TRUNCATED_MARKER = "RKA_ADB_OUTPUT_TRUNCATED\n"
        val REAP_TIMEOUT: Duration = Duration.ofSeconds(3)
        const val REAP_POLL_NANOS = 10_000_000L
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
