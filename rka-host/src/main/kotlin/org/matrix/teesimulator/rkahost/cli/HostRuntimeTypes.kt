package org.matrix.teesimulator.rkahost.cli

import java.time.Duration
import java.util.concurrent.TimeUnit

internal const val RKA_CONTROL_PATH = "/data/adb/modules/tricky_store/rka-control.sh"
internal const val RKA_RELEASE_REMOTE = "/data/local/tmp/teesimulator-rka.zip"

data class HostCommandResult(val exitCode: Int, val stdout: String, val stderr: String)

fun interface HostCommandRunner {
    fun run(argv: List<String>): HostCommandResult

    fun runRoot(serial: BoundSerial, script: String, arguments: List<String>): HostCommandResult =
        run(listOf("adb", "-s", serial.value, "shell", "su", "0", "sh") + arguments)
}

class ProcessHostCommandRunner : HostCommandRunner {
    override fun run(argv: List<String>): HostCommandResult = execute(argv, null)

    override fun runRoot(
        serial: BoundSerial,
        script: String,
        arguments: List<String>,
    ): HostCommandResult {
        if (
            !script.endsWith('\n') ||
                arguments.any { !it.matches(Regex("[A-Za-z0-9_./:-]{1,1024}")) }
        ) {
            throw HostCliException("ROOT_INPUT_INVALID")
        }
        val payload = buildString {
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
