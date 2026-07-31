package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Path

class HostOrchestrator(
    private val pair: DevicePairSnapshot,
    private val runner: HostCommandRunner,
) {
    private val calls = mutableListOf<List<String>>()
    private val binding = PairBinding.from(pair)

    fun profilePair() {
        control(pair.donor, "profile-pair", "DONOR")
        control(pair.candidate, "profile-pair", "CANDIDATE")
    }

    fun deployNoReboot(releaseZip: String) {
        if (releaseZip.isBlank()) throw HostCliException("RELEASE_PATH_INVALID")
        for (serial in serials()) {
            invoke(listOf("adb", "-s", serial.value, "push", releaseZip, RKA_RELEASE_REMOTE))
            control(serial, "deploy-no-reboot", RKA_RELEASE_REMOTE)
        }
    }

    fun snapshot(kind: String): Map<String, String> {
        val command =
            when (kind) {
                "capability" -> listOf("shell", "getprop", "ro.build.version.release")
                "config" -> listOf("shell", "sh", RKA_CONTROL_PATH, "snapshot-config")
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
        recoverPending(path)
        BaselineStore.requireReadyAbsent(path)
        val baseline =
            SentinelBaseline(
                sentinelId = Hashes.sha256("${binding.pairHash}:$nonce".toByteArray()),
                nonce = nonce,
                binding = binding,
                donorBootId = bootId(pair.donor),
                candidateBootId = bootId(pair.candidate),
                donorStartMillis = monotonicMillis(pair.donor),
                candidateStartMillis = monotonicMillis(pair.candidate),
            )
        BaselineStore.createPending(path, baseline)
        try {
            sentinelOne(pair.donor, baseline, "start")
            sentinelOne(pair.candidate, baseline, "start")
            validateStarted(baseline)
            BaselineStore.commitPending(path, baseline)
            return baseline
        } catch (failure: HostCliException) {
            if (cleanupSentinel(baseline)) BaselineStore.abortPending(path)
            throw failure
        }
    }

    fun sentinelSample(path: Path): SentinelSample {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
        sentinelAction(baseline, "sample")
        return sample(baseline)
    }

    fun sentinelFinish(path: Path): SentinelSample {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
        sentinelAction(baseline, "finish")
        return sample(baseline)
    }

    fun sentinelVerify(path: Path) {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
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
        serials().forEach { sentinelOne(it, baseline, action) }
    }

    private fun sentinelOne(serial: BoundSerial, baseline: SentinelBaseline, action: String) {
        val result =
            invoke(
                adb(
                    serial,
                    listOf(
                        "shell",
                        "sh",
                        RKA_CONTROL_PATH,
                        "sentinel",
                        action,
                        "--id",
                        baseline.sentinelId,
                        "--nonce",
                        baseline.nonce,
                    ),
                )
            )
        val expected = "sentinel_id=${baseline.sentinelId} nonce=${baseline.nonce} action=$action"
        if (result.stdout.trim() != expected) throw HostCliException("SENTINEL_RESPONSE_INVALID")
    }

    private fun validateStarted(baseline: SentinelBaseline) {
        if (
            bootId(pair.donor) != baseline.donorBootId ||
                bootId(pair.candidate) != baseline.candidateBootId
        ) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            monotonicMillis(pair.donor) < baseline.donorStartMillis ||
                monotonicMillis(pair.candidate) < baseline.candidateStartMillis
        ) {
            throw HostCliException("SENTINEL_MONOTONIC_INVALID")
        }
    }

    private fun recoverPending(path: Path) {
        if (!BaselineStore.hasPending(path)) return
        if (BaselineStore.finalizeCommittedPending(path)) return
        val baseline = BaselineStore.readPending(path)
        requirePair(baseline)
        if (!cleanupSentinel(baseline)) throw HostCliException("SENTINEL_RECOVERY_FAILED")
        BaselineStore.abortPending(path)
    }

    private fun cleanupSentinel(baseline: SentinelBaseline): Boolean {
        var succeeded = true
        for (serial in serials()) {
            try {
                control(
                    serial,
                    "sentinel",
                    "cleanup",
                    "--id",
                    baseline.sentinelId,
                    "--nonce",
                    baseline.nonce,
                )
            } catch (_: HostCliException) {
                succeeded = false
            }
        }
        return succeeded
    }

    private fun requirePair(baseline: SentinelBaseline) {
        if (baseline.binding != binding) throw HostCliException("PAIR_BINDING_MISMATCH")
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
        invoke(adb(serial, listOf("shell", "sh", RKA_CONTROL_PATH) + arguments))
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
}
