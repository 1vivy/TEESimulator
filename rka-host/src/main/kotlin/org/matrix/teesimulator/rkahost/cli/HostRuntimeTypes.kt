package org.matrix.teesimulator.rkahost.cli

import java.time.Duration
import java.util.concurrent.TimeUnit

internal const val RKA_CONTROL_PATH = "/data/adb/modules/tricky_store/rka-control.sh"
internal const val RKA_RELEASE_REMOTE = "/data/local/tmp/teesimulator-rka.zip"

data class HostCommandResult(val exitCode: Int, val stdout: String, val stderr: String)

fun interface HostCommandRunner {
    fun run(argv: List<String>): HostCommandResult
}

class ProcessHostCommandRunner : HostCommandRunner {
    override fun run(argv: List<String>): HostCommandResult {
        val process =
            try {
                ProcessBuilder(argv).start()
            } catch (_: Exception) {
                throw HostCliException("ADB_START_FAILED")
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
)
