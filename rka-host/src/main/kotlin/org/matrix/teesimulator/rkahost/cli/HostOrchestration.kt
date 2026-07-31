package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit

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

class HostOrchestrator(
    private val pair: DevicePairSnapshot,
    private val runner: HostCommandRunner,
) {
    private val calls = mutableListOf<List<String>>()

    fun profilePair() {
        control(pair.donor, "profile-pair", "DONOR")
        control(pair.candidate, "profile-pair", "CANDIDATE")
    }

    fun deployNoReboot(releaseZip: String) {
        if (releaseZip.isBlank()) throw HostCliException("RELEASE_PATH_INVALID")
        for (serial in serials()) {
            invoke(listOf("adb", "-s", serial.value, "push", releaseZip, RELEASE_REMOTE))
            control(serial, "deploy-no-reboot", RELEASE_REMOTE)
        }
    }

    fun snapshot(kind: String): Map<String, String> {
        val command =
            when (kind) {
                "capability" -> listOf("shell", "getprop", "ro.build.version.release")
                "config" -> listOf("shell", "sh", CONTROL, "snapshot-config")
                else -> throw HostCliException("SNAPSHOT_KIND_INVALID")
            }
        return serials().associate { it.value to invoke(adb(it, command)).stdout.trim() }
    }

    fun lifecycle(action: String) {
        if (action !in setOf("status", "start", "stop")) {
            throw HostCliException("LIFECYCLE_ACTION_INVALID")
        }
        serials().forEach { control(it, "lifecycle", action) }
    }

    fun recoverExact(service: String) {
        if (service !in setOf("keystore2", "rkpd")) {
            throw HostCliException("RECOVERY_SERVICE_INVALID")
        }
        invoke(adb(pair.donor, listOf("shell", "setprop", "ctl.restart", service)))
    }

    fun cleanup() {
        serials().forEach { control(it, "cleanup") }
    }

    fun sentinelStart(path: Path, nonce: String): SentinelBaseline {
        val baseline =
            SentinelBaseline(
                sentinelId =
                    Hashes.sha256(
                        "${Hashes.sha256(pair.canonical().toByteArray())}:$nonce".toByteArray()
                    ),
                nonce = nonce,
                pairHash = Hashes.sha256(pair.canonical().toByteArray()),
                donorBootId = bootId(pair.donor),
                candidateBootId = bootId(pair.candidate),
                donorStartMillis = monotonicMillis(pair.donor),
                candidateStartMillis = monotonicMillis(pair.candidate),
            )
        BaselineStore.create(path, baseline)
        sentinelAction(baseline, "start")
        return baseline
    }

    fun sentinelSample(path: Path): SentinelSample {
        val baseline = BaselineStore.read(path)
        sentinelAction(baseline, "sample")
        return sample(baseline)
    }

    fun sentinelFinish(path: Path): SentinelSample {
        val baseline = BaselineStore.read(path)
        sentinelAction(baseline, "finish")
        return sample(baseline)
    }

    fun sentinelVerify(path: Path) {
        val baseline = BaselineStore.read(path)
        sentinelAction(baseline, "verify")
        val current = sample(baseline)
        if (
            current.donorBootId != baseline.donorBootId ||
                current.candidateBootId != baseline.candidateBootId
        ) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            current.donorMillis <= baseline.donorStartMillis ||
                current.candidateMillis <= baseline.candidateStartMillis
        ) {
            throw HostCliException("SENTINEL_MONOTONIC_INVALID")
        }
    }

    fun trace(): List<List<String>> = calls.map { it.toList() }

    private fun sample(baseline: SentinelBaseline): SentinelSample =
        SentinelSample(
            baseline.sentinelId,
            bootId(pair.donor),
            bootId(pair.candidate),
            monotonicMillis(pair.donor),
            monotonicMillis(pair.candidate),
        )

    private fun sentinelAction(baseline: SentinelBaseline, action: String) {
        serials().forEach {
            control(it, "sentinel", action, "--id", baseline.sentinelId, "--nonce", baseline.nonce)
        }
    }

    private fun bootId(serial: BoundSerial): String =
        invoke(adb(serial, listOf("shell", "cat", "/proc/sys/kernel/random/boot_id")))
            .stdout
            .trim()
            .also {
                if (!it.matches(Regex("[A-Za-z0-9._-]{1,128}"))) {
                    throw HostCliException("BOOT_ID_INVALID")
                }
            }

    private fun monotonicMillis(serial: BoundSerial): Long {
        val seconds =
            invoke(adb(serial, listOf("shell", "cat", "/proc/uptime")))
                .stdout
                .trim()
                .substringBefore(' ')
                .toBigDecimalOrNull() ?: throw HostCliException("UPTIME_INVALID")
        return seconds.movePointRight(3).toLong()
    }

    private fun control(serial: BoundSerial, vararg arguments: String) {
        invoke(adb(serial, listOf("shell", "sh", CONTROL) + arguments))
    }

    private fun adb(serial: BoundSerial, arguments: List<String>): List<String> =
        listOf("adb", "-s", serial.value) + arguments

    private fun invoke(argv: List<String>): HostCommandResult {
        if (
            argv.any {
                it.lowercase() in setOf("reboot", "killall", "pkill", "stop", "start") &&
                    it !in setOf("start", "stop")
            }
        ) {
            throw HostCliException("FORBIDDEN_DEVICE_COMMAND")
        }
        if (argv.take(2) != listOf("adb", "-s") || argv.getOrNull(2) !in serialValues()) {
            throw HostCliException("UNBOUND_DEVICE_COMMAND")
        }
        calls += argv.toList()
        val result = runner.run(argv)
        if (result.exitCode != 0) throw HostCliException("ADB_COMMAND_FAILED")
        return result
    }

    private fun serials(): List<BoundSerial> = listOf(pair.donor, pair.candidate)

    private fun serialValues(): Set<String> = serials().mapTo(mutableSetOf()) { it.value }

    companion object {
        private const val CONTROL = "/data/adb/modules/tricky_store/rka-control.sh"
        private const val RELEASE_REMOTE = "/data/local/tmp/teesimulator-rka.zip"
    }
}

data class SentinelSample(
    val sentinelId: String,
    val donorBootId: String,
    val candidateBootId: String,
    val donorMillis: Long,
    val candidateMillis: Long,
)
