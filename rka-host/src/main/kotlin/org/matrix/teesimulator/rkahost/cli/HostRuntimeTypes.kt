package org.matrix.teesimulator.rkahost.cli

import java.time.Duration
import java.util.concurrent.TimeUnit
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

class ProcessHostCommandRunner : HostCommandRunner {
    override fun run(argv: List<String>): HostCommandResult = execute(argv, null)

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
                arguments.any { !it.matches(Regex("[A-Za-z0-9_./:-]{1,1024}")) }
        ) {
            throw HostCliException("ROOT_INPUT_INVALID")
        }
        val payload = buildString {
            append("exec 3<<'RKA_PRIVATE_INPUT_V1'\n")
            append(privateInput.canonical)
            append("RKA_PRIVATE_INPUT_V1\n")
            append("set --")
            arguments.forEach { append(' ').append(it) }
            append('\n').append(script)
        }
        return execute(listOf("adb", "-s", serial.value, "shell", "su", "0", "sh"), payload)
    }

    private fun execute(argv: List<String>, stdin: String?): HostCommandResult {
        val process =
            try {
                ProcessBuilder(argv).start()
            } catch (_: Exception) {
                throw HostCliException("ADB_START_FAILED")
            }
        try {
            process.outputStream.use { output ->
                if (stdin != null) output.write(stdin.toByteArray(Charsets.UTF_8))
            }
        } catch (_: Exception) {
            process.destroyForcibly()
            throw HostCliException("ADB_STDIN_FAILED")
        }
        if (!process.waitFor(Duration.ofSeconds(30).toMillis(), TimeUnit.MILLISECONDS)) {
            process.destroyForcibly()
            throw HostCliException("ADB_TIMEOUT")
        }
        return HostCommandResult(
            process.exitValue(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
        )
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
