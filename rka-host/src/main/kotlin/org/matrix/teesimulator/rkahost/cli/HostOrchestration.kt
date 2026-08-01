package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Path
import org.matrix.teesimulator.rkahost.evidence.donorPropertyPrivateInput

class HostOrchestrator(
    private val pair: DevicePairSnapshot,
    private val delegateRunner: HostCommandRunner,
    initialTrace: PersistentAdbTrace? = null,
) {
    private var trace = initialTrace
    private val binding = PairBinding.from(pair)
    private val sentinelScript =
        checkNotNull(javaClass.getResourceAsStream("/rka-preinstall-sentinel.sh")) {
                "SENTINEL_RESOURCE_MISSING"
            }
            .bufferedReader()
            .readText()
            .also { if (!it.endsWith('\n')) throw HostCliException("SENTINEL_RESOURCE_INVALID") }
    private val sentinelScriptHash = Hashes.sha256(sentinelScript.toByteArray())

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

    fun recoverExact(role: String, service: String) {
        ExactRecoveryCli(ControlScriptRecoveryTransport(pair, ::invoke))
            .recover(ExactRecoveryCli.parseRole(role), ExactRecoveryCli.parseTarget(service))
    }

    fun cleanup() {
        serials().forEach { control(it, "cleanup") }
    }

    fun sentinelStart(
        path: Path,
        nonce: String,
        scope: SentinelScope = SentinelScope.PAIR,
    ): SentinelBaseline {
        recoverPending(path)
        BaselineStore.requireReadyAbsent(path)
        val sentinelId = Hashes.sha256("${binding.pairHash}:$nonce".toByteArray())
        val journal = PersistentAdbTrace.create(path, binding, sentinelId, nonce)
        trace = journal
        val initialTraceBinding = journal.validateClean().binding
        val baseline =
            SentinelBaseline(
                sentinelId = sentinelId,
                nonce = nonce,
                binding = binding,
                donorBootId = bootIdentityHash(pair.donor),
                candidateBootId =
                    if (scope == SentinelScope.PAIR) bootIdentityHash(pair.candidate)
                    else "DONOR_SCOPE",
                donorStartMillis = monotonicMillis(pair.donor),
                candidateStartMillis =
                    if (scope == SentinelScope.PAIR) monotonicMillis(pair.candidate) else 0,
                authority = SentinelPhase.ROOT_AUTHORITATIVE,
                samplerSha256 = sentinelScriptHash,
                scope = scope,
                commandTraceGenesisSha256 = initialTraceBinding.genesisSha256,
                commandTraceSessionId = initialTraceBinding.sessionId,
                commandTraceInitialHeadSha256 = initialTraceBinding.headSha256,
                commandTraceInitialEventCount = initialTraceBinding.eventCount,
            )
        BaselineStore.createPending(path, baseline)
        try {
            sentinelOne(pair.donor, baseline, "start")
            if (scope == SentinelScope.PAIR) sentinelOne(pair.candidate, baseline, "start")
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
        attachTrace(path, baseline)
        return sample(baseline, sentinelAction(baseline, "sample"))
    }

    fun sentinelFinish(path: Path): SentinelSample {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
        attachTrace(path, baseline)
        return sample(baseline, sentinelAction(baseline, "assert-live"))
    }

    fun sentinelVerify(path: Path) {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
        attachTrace(path, baseline)
        val current = sample(baseline, sentinelAction(baseline, "assert-live"))
        if (
            current.donorBootId != baseline.donorBootId ||
                current.candidateBootId != baseline.candidateBootId
        ) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            current.donorMillis <= baseline.donorStartMillis ||
                (baseline.scope == SentinelScope.PAIR &&
                    current.candidateMillis <= baseline.candidateStartMillis)
        ) {
            throw HostCliException("SENTINEL_MONOTONIC_INVALID")
        }
    }

    fun sentinelAssertLive(path: Path): SentinelSample = sentinelFinish(path)

    fun sentinelStop(path: Path) {
        val baseline = BaselineStore.read(path)
        requirePair(baseline)
        attachTrace(path, baseline)
        sentinelAction(baseline, "stop")
        BaselineStore.delete(path, baseline)
    }

    fun persistentTrace(): ValidatedPersistentTrace =
        trace?.snapshotForReceipt() ?: throw HostCliException("COMMAND_TRACE_MISSING")

    private fun sample(
        baseline: SentinelBaseline,
        phase: SentinelPhase = SentinelPhase.ROOT_AUTHORITATIVE,
    ): SentinelSample =
        SentinelSample(
            baseline.sentinelId,
            bootIdentityHash(pair.donor),
            if (baseline.scope == SentinelScope.PAIR) bootIdentityHash(pair.candidate)
            else baseline.candidateBootId,
            monotonicMillis(pair.donor),
            if (baseline.scope == SentinelScope.PAIR) monotonicMillis(pair.candidate)
            else baseline.candidateStartMillis,
            phase,
        )

    private fun sentinelAction(baseline: SentinelBaseline, action: String): SentinelPhase =
        sentinelSerials(baseline)
            .map { sentinelOne(it, baseline, action) }
            .let { phases ->
                if (phases.all { it == SentinelPhase.INSTALLED_OBSERVED }) {
                    SentinelPhase.INSTALLED_OBSERVED
                } else {
                    SentinelPhase.ROOT_AUTHORITATIVE
                }
            }

    private fun sentinelOne(
        serial: BoundSerial,
        baseline: SentinelBaseline,
        action: String,
    ): SentinelPhase {
        val role = if (serial == pair.donor) "DONOR" else "CANDIDATE"
        val argv = listOf("adb", "-s", serial.value, "shell", "su", "0", "sh")
        val result =
            tracedRunner()
                .runRoot(
                    serial,
                    sentinelScript,
                    listOf(
                        action,
                        baseline.sentinelId,
                        Hashes.sha256(baseline.nonce.toByteArray()),
                        role,
                        sentinelScriptHash,
                    ) + SentinelLimits.PRE_INSTALL.arguments(),
                    if (role == "DONOR") donorPropertyPrivateInput() else RootPrivateInput.EMPTY,
                )
        if (result.exitCode != 0) {
            val terminal = Regex(".* result=(SENTINEL_[A-Z_]+)").matchEntire(result.stdout.trim())
            throw HostCliException(terminal?.groupValues?.get(1) ?: "ADB_COMMAND_FAILED")
        }
        val response =
            Regex(
                    "sentinel_id=${baseline.sentinelId} action=${Regex.escape(action)} phase=([A-Z_]+) samples=([0-9]+)"
                )
                .matchEntire(result.stdout.trim())
                ?: throw HostCliException("SENTINEL_RESPONSE_INVALID")
        val samples =
            response.groupValues[2].toIntOrNull()
                ?: throw HostCliException("SENTINEL_RESPONSE_INVALID")
        if (
            samples !in 0..SentinelLimits.PRE_INSTALL.maximumSamples ||
                (action == "start" && samples != 1) ||
                (action in setOf("sample", "assert-live") && samples < 2)
        ) {
            throw HostCliException("SENTINEL_RESPONSE_INVALID")
        }
        return when (response.groupValues[1]) {
            "INSTALLED_OBSERVED" -> SentinelPhase.INSTALLED_OBSERVED
            "ROOT_AUTHORITATIVE",
            "STOPPED" -> SentinelPhase.ROOT_AUTHORITATIVE
            else -> throw HostCliException("SENTINEL_RESPONSE_INVALID")
        }
    }

    private fun validateStarted(baseline: SentinelBaseline) {
        if (
            bootIdentityHash(pair.donor) != baseline.donorBootId ||
                (baseline.scope == SentinelScope.PAIR &&
                    bootIdentityHash(pair.candidate) != baseline.candidateBootId)
        ) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            monotonicMillis(pair.donor) < baseline.donorStartMillis ||
                (baseline.scope == SentinelScope.PAIR &&
                    monotonicMillis(pair.candidate) < baseline.candidateStartMillis)
        ) {
            throw HostCliException("SENTINEL_MONOTONIC_INVALID")
        }
    }

    private fun recoverPending(path: Path) {
        if (!BaselineStore.hasPending(path)) return
        if (BaselineStore.finalizeCommittedPending(path)) return
        val baseline = BaselineStore.readPending(path)
        requirePair(baseline)
        attachTrace(path, baseline)
        if (!cleanupSentinel(baseline)) throw HostCliException("SENTINEL_RECOVERY_FAILED")
        BaselineStore.abortPending(path)
    }

    private fun cleanupSentinel(baseline: SentinelBaseline): Boolean {
        var succeeded = true
        for (serial in sentinelSerials(baseline)) {
            try {
                sentinelOne(serial, baseline, "stop")
            } catch (_: HostCliException) {
                succeeded = false
            }
        }
        return succeeded
    }

    private fun requirePair(baseline: SentinelBaseline) {
        if (baseline.binding != binding) throw HostCliException("PAIR_BINDING_MISMATCH")
    }

    private fun bootIdentityHash(serial: BoundSerial): String {
        val raw =
            invoke(adb(serial, listOf("shell", "cat", "/proc/sys/kernel/random/boot_id")))
                .stdout
                .trim()
        if (!raw.matches(Regex("[A-Za-z0-9._-]{1,128}"))) {
            throw HostCliException("BOOT_ID_INVALID")
        }
        return Hashes.sha256(raw.toByteArray())
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
        if (argv.take(2) != listOf("adb", "-s") || argv.getOrNull(2) !in serialValues()) {
            throw HostCliException("UNBOUND_DEVICE_COMMAND")
        }
        val result = tracedRunner().run(argv)
        if (result.exitCode != 0) throw HostCliException("ADB_COMMAND_FAILED")
        return result
    }

    private fun serials(): List<BoundSerial> = listOf(pair.donor, pair.candidate)

    private fun sentinelSerials(baseline: SentinelBaseline): List<BoundSerial> =
        if (baseline.scope == SentinelScope.DONOR) listOf(pair.donor) else serials()

    private fun serialValues(): Set<String> = serials().mapTo(mutableSetOf()) { it.value }

    private fun attachTrace(path: Path, baseline: SentinelBaseline) {
        trace = PersistentAdbTrace.open(path, baseline)
        val current =
            trace?.validateClean()?.binding ?: throw HostCliException("COMMAND_TRACE_MISSING")
        if (
            current.genesisSha256 != baseline.commandTraceGenesisSha256 ||
                current.sessionId != baseline.commandTraceSessionId ||
                baseline.commandTraceInitialHeadSha256 != baseline.commandTraceGenesisSha256 ||
                baseline.commandTraceInitialEventCount != 0
        ) {
            throw HostCliException("COMMAND_TRACE_BINDING_MISMATCH")
        }
    }

    private fun tracedRunner(): HostCommandRunner =
        trace?.let { TracedHostCommandRunner(delegateRunner, it) }
            ?: if (delegateRunner is ProcessHostCommandRunner) {
                throw HostCliException("COMMAND_TRACE_MISSING")
            } else {
                delegateRunner
            }
}
