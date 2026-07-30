package org.matrix.teesimulator.rkahost

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class CandidateTlsOwner {
    ROOT_DAEMON,
    CANDIDATE_COMPANION,
}

data class OwnerAttempt(
    val owner: CandidateTlsOwner,
    val proven: Boolean,
    val failureCause: String?,
)

data class HostGateDecision(
    val proven: Boolean,
    val selectedOwner: CandidateTlsOwner?,
    val errorCode: String?,
    val failureCauses: List<String>,
    val task6Marker: Boolean = false,
)

object CandidateOwnerSelector {
    fun select(root: OwnerAttempt, fallback: () -> OwnerAttempt): HostGateDecision {
        require(root.owner == CandidateTlsOwner.ROOT_DAEMON)
        if (root.proven) return HostGateDecision(true, root.owner, null, emptyList())
        val companion = fallback()
        require(companion.owner == CandidateTlsOwner.CANDIDATE_COMPANION)
        if (companion.proven) return HostGateDecision(true, companion.owner, null, emptyList())
        return HostGateDecision(
            proven = false,
            selectedOwner = null,
            errorCode = "CANDIDATE_TLS_OWNER_UNPROVEN",
            failureCauses =
                listOf(
                    "ROOT_DAEMON:${root.failureCause ?: "ASSERTION_FAILED"}",
                    "CANDIDATE_COMPANION:${companion.failureCause ?: "ASSERTION_FAILED"}",
                ),
        )
    }
}

object CandidateIdentityGateCli {
    internal const val PACKAGE = "org.matrix.teesimulator.rkafixture.candidateprobe"
    internal const val TEST_PACKAGE = "$PACKAGE.test"
    internal const val MAIN_CLASS = "org.matrix.teesimulator.rkafixture.CandidateRootProbe"
    private const val REQUIRED_STATES =
        "IDENTITY_CREATED,PUBLIC_TRUST_STAGED,PROFILE_STAGED,LISTENER_READY,TLS_PROVED,ACTIVE"
    private val defaultApk =
        Path.of(
            "rka-fixture",
            "build",
            "outputs",
            "apk",
            "candidateProbe",
            "rka-fixture-candidateProbe.apk",
        )
    private val defaultTestApk =
        Path.of(
            "rka-fixture",
            "build",
            "outputs",
            "apk",
            "androidTest",
            "candidateProbe",
            "rka-fixture-candidateProbe-androidTest.apk",
        )

    @JvmStatic
    fun main(arguments: Array<String>) {
        val exit = run(arguments)
        if (exit != 0) kotlin.system.exitProcess(exit)
    }

    internal fun run(
        arguments: Array<String>,
        runnerFactory: (DeviceSerial) -> CandidateAdb = { CandidateAdb(it) },
    ): Int {
        val candidate = parseCandidate(arguments) ?: return fail("ARGUMENT_INVALID")
        if (!candidate.value.contains(':')) return fail("CANDIDATE_NETWORK_SERIAL_REQUIRED")
        val runner = runnerFactory(candidate)
        var installed = false
        var testInstalled = false
        var apkPath: String? = null
        return try {
            runner.requireSuccess(listOf("get-state"), "CANDIDATE_UNREACHABLE")
            check(!runner.packagePath().isPresent) { "CANDIDATE_PROBE_PACKAGE_PREEXISTS" }
            check(runner.profileAbsentOrCompanion()) { "CANDIDATE_PROFILE_CONFLICT" }
            val localApk = System.getenv("RKA_CANDIDATE_PROBE_APK")?.let(Path::of) ?: defaultApk
            check(Files.isRegularFile(localApk)) { "CANDIDATE_PROBE_APK_MISSING" }
            runner.requireSuccess(
                listOf("install", localApk.toAbsolutePath().normalize().toString()),
                "CANDIDATE_PROBE_INSTALL_FAILED",
                Duration.ofSeconds(60),
            )
            installed = true
            apkPath = runner.packagePath().validatedPath()

            val preBoot = runner.bootHash()
            val pre = runner.rootProbe(requireNotNull(apkPath), "pre")
            val rootAttempt =
                OwnerAttempt(
                    CandidateTlsOwner.ROOT_DAEMON,
                    pre.isValid(expectedGenerateCount = 1, expectedPhase = "PRE"),
                    pre.failure(),
                )
            var selectedPre = pre
            val initial =
                if (rootAttempt.proven) {
                    HostGateDecision(true, CandidateTlsOwner.ROOT_DAEMON, null, emptyList())
                } else {
                    check(Files.isRegularFile(defaultTestApk)) {
                        "CANDIDATE_PROBE_TEST_APK_MISSING"
                    }
                    runner.requireSuccess(
                        listOf("install", defaultTestApk.toAbsolutePath().normalize().toString()),
                        "CANDIDATE_PROBE_TEST_INSTALL_FAILED",
                        Duration.ofSeconds(60),
                    )
                    testInstalled = true
                    val companionPre = runner.companionProbe("PRE")
                    selectedPre = companionPre
                    CandidateOwnerSelector.select(rootAttempt) {
                        OwnerAttempt(
                            CandidateTlsOwner.CANDIDATE_COMPANION,
                            companionPre.isValid(1, "PRE"),
                            companionPre.failure(),
                        )
                    }
                }
            if (!initial.proven) return emitDecision(initial)

            runner.rebootAndReconnect()
            val postBoot = runner.bootHash()
            check(preBoot != postBoot) { "REBOOT_RECEIPT_INVALID" }
            val post =
                if (initial.selectedOwner == CandidateTlsOwner.ROOT_DAEMON) {
                    runner.rootProbe(requireNotNull(apkPath), "post")
                } else {
                    runner.companionProbe("POST")
                }
            check(post.isValid(expectedGenerateCount = 0, expectedPhase = "POST")) {
                post.failure()
            }
            val selected = requireNotNull(initial.selectedOwner)
            runner.rootAction(
                requireNotNull(apkPath),
                if (selected == CandidateTlsOwner.ROOT_DAEMON) {
                    "persist-root-profile"
                } else {
                    "persist-companion-profile"
                },
            )

            println("SCHEMA_VERSION=1")
            println("RESULT=PROVEN")
            println("SELECTED_OWNER=${selected.name}")
            println("OWNER_COUNT=1")
            println("PRE_BOOT_HASH=$preBoot")
            println("POST_BOOT_HASH=$postBoot")
            println("PRE_STATE_SEQUENCE=${selectedPre.fields["STATE_SEQUENCE"]}")
            println("POST_STATE_SEQUENCE=${post.fields["STATE_SEQUENCE"]}")
            println("PRIVATE_KEY_ENCODED_NULL=true")
            println("INSIDE_SECURITY_HARDWARE=true")
            println("TEE_SECURITY_LEVEL=true")
            println("EC_P256=true")
            println("TLS_PROTOCOL=TLSv1.3")
            println("CLIENT_CERT_REQUIRED=true")
            println("PINNED_PEER=true")
            println("INTERCEPTOR_REENTRY_COUNT=0")
            println("CANDIDATE_LOCAL_GENERATE_COUNT_PRE=1")
            println("CANDIDATE_LOCAL_GENERATE_COUNT_POST=0")
            println("WATCHDOG_TIMED_OUT=false")
            println("PROFILE=VERSION_1_${selected.name}")
            rootAttempt.failureCause?.let { println("ROOT_FAILURE=$it") }
            0
        } catch (failure: Throwable) {
            fail(failure.message?.typedCode() ?: "CANDIDATE_TLS_OWNER_UNPROVEN")
        } finally {
            if (installed) {
                if (testInstalled) {
                    runCatching { runner.companionProbe("CLEANUP") }
                    runCatching {
                        runner.requireSuccess(listOf("uninstall", TEST_PACKAGE), "CLEANUP_FAILED")
                    }
                }
                if (apkPath != null) {
                    runCatching { runner.rootAction(requireNotNull(apkPath), "cleanup") }
                }
                runCatching {
                    runner.requireSuccess(listOf("uninstall", PACKAGE), "CLEANUP_FAILED")
                }
            }
        }
    }

    private fun parseCandidate(arguments: Array<String>): DeviceSerial? {
        val expected =
            listOf(
                "candidate-identity-gate",
                "--candidate",
                "<serial>",
                "--prefer",
                "ROOT_DAEMON",
                "--allow-fallback",
                "CANDIDATE_COMPANION",
                "--reboot",
            )
        if (arguments.size != expected.size) return null
        if (
            arguments[0] != expected[0] ||
                arguments[1] != expected[1] ||
                arguments[3] != expected[3] ||
                arguments[4] != expected[4] ||
                arguments[5] != expected[5] ||
                arguments[6] != expected[6] ||
                arguments[7] != expected[7]
        )
            return null
        return runCatching { DeviceSerial.of(DeviceRole.CANDIDATE, arguments[2]) }.getOrNull()
    }

    private fun emitDecision(decision: HostGateDecision): Int {
        println("RESULT=${decision.errorCode}")
        println("OWNER_COUNT=0")
        println("TASK6_MARKER=${decision.task6Marker}")
        decision.failureCauses.forEachIndexed { index, cause ->
            println("FAILURE_${index + 1}=$cause")
        }
        return 1
    }

    private fun fail(code: String): Int {
        println("RESULT=${code.typedCode()}")
        println("OWNER_COUNT=0")
        println("TASK6_MARKER=false")
        return 1
    }

    private fun String.typedCode(): String =
        uppercase().replace(Regex("[^A-Z0-9_:-]"), "_").take(128)
}

internal class CandidateAdb(
    private val candidate: DeviceSerial,
    private val adbPath: String =
        System.getenv("ANDROID_HOME")?.let { Path.of(it, "platform-tools", "adb").toString() }
            ?: "adb",
) {
    fun requireSuccess(
        tail: List<String>,
        error: String,
        timeout: Duration = Duration.ofSeconds(30),
    ): ByteArray {
        val result = execute(tail, timeout)
        check(result.exitCode == 0) { error }
        return result.stdout
    }

    fun packagePath(): PackagePath {
        val result =
            execute(
                listOf("shell", "cmd", "package", "path", CandidateIdentityGateCli.PACKAGE),
                Duration.ofSeconds(10),
            )
        val output = result.stdout.decodeToString().trim()
        check(result.exitCode == 0 || output.isEmpty()) { "PACKAGE_QUERY_FAILED" }
        return PackagePath(output.removePrefix("package:").ifBlank { null })
    }

    fun profileAbsentOrCompanion(): Boolean {
        val result =
            execute(
                listOf(
                    "shell",
                    "su",
                    "0",
                    "cat",
                    "/data/adb/tricky_store/rka-candidate-owner.conf",
                ),
                Duration.ofSeconds(10),
            )
        if (result.exitCode != 0) return true
        return result.stdout.decodeToString().replace("\r", "") ==
            "version=1\nowner=CANDIDATE_COMPANION\n"
    }

    fun bootHash(): String {
        val raw =
            requireSuccess(
                listOf("shell", "cat", "/proc/sys/kernel/random/boot_id"),
                "BOOT_RECEIPT_FAILED",
            )
        return MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") {
            "%02x".format(it)
        }
    }

    fun rootProbe(apkPath: String, phase: String): ProbeOutput {
        requireSuccess(listOf("logcat", "-c"), "LOGCAT_CLEAR_FAILED")
        val output = rootAction(apkPath, phase)
        val logs =
            requireSuccess(listOf("logcat", "-d", "-v", "brief"), "LOGCAT_READ_FAILED")
                .decodeToString()
        val reentries =
            logs.lineSequence().count {
                it.contains("Hijacking Transaction") && it.contains("TEESimulator")
            }
        return ProbeOutput.parse(output.decodeToString(), reentries)
    }

    fun companionProbe(phase: String): ProbeOutput {
        requireSuccess(listOf("logcat", "-c"), "LOGCAT_CLEAR_FAILED")
        val output =
            requireSuccess(
                    listOf(
                        "shell",
                        "am",
                        "instrument",
                        "-w",
                        "-e",
                        "class",
                        "org.matrix.teesimulator.rkafixture.CandidateCompanionProbeTest",
                        "-e",
                        "phase",
                        phase,
                        "${CandidateIdentityGateCli.TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner",
                    ),
                    "COMPANION_PROBE_COMMAND_FAILED",
                )
                .decodeToString()
        val receipt =
            output
                .lineSequence()
                .firstOrNull { it.contains("candidate_receipt=") }
                ?.substringAfter("candidate_receipt=")
                ?.replace(';', '\n') ?: error("COMPANION_RECEIPT_MISSING")
        val logs =
            requireSuccess(listOf("logcat", "-d", "-v", "brief"), "LOGCAT_READ_FAILED")
                .decodeToString()
        val reentries =
            logs.lineSequence().count {
                it.contains("Hijacking Transaction") && it.contains("TEESimulator")
            }
        return ProbeOutput.parse(receipt, reentries)
    }

    fun rootAction(apkPath: String, action: String): ByteArray {
        check(PackagePath.pattern.matches(apkPath)) { "PACKAGE_PATH_INVALID" }
        return requireSuccess(
            listOf(
                "shell",
                "su",
                "0",
                "env",
                "CLASSPATH=$apkPath",
                "app_process",
                "/system/bin",
                CandidateIdentityGateCli.MAIN_CLASS,
                action,
            ),
            "ROOT_PROBE_COMMAND_FAILED",
        )
    }

    fun rebootAndReconnect() {
        requireSuccess(listOf("reboot"), "REBOOT_COMMAND_FAILED")
        val deadline = System.nanoTime() + Duration.ofSeconds(120).toNanos()
        while (System.nanoTime() < deadline) {
            val state = execute(listOf("get-state"), Duration.ofSeconds(5))
            if (state.exitCode == 0) {
                val complete =
                    execute(listOf("shell", "getprop", "sys.boot_completed"), Duration.ofSeconds(5))
                if (complete.exitCode == 0 && complete.stdout.decodeToString().trim() == "1") return
            }
            Thread.sleep(1000)
        }
        error("CANDIDATE_RECONNECT_TIMEOUT")
    }

    private fun execute(tail: List<String>, timeout: Duration): ProcessResult {
        val process = ProcessBuilder(listOf(adbPath, "-s", candidate.value) + tail).start()
        val executor = Executors.newFixedThreadPool(2)
        return try {
            val stdout = executor.submit(Callable { process.inputStream.readBytes() })
            val stderr = executor.submit(Callable { process.errorStream.readBytes() })
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                error("ADB_TIMEOUT")
            }
            ProcessResult(process.exitValue(), stdout.get(), stderr.get())
        } finally {
            process.destroyForcibly()
            executor.shutdownNow()
        }
    }

    internal data class PackagePath(val value: String?) {
        val isPresent: Boolean
            get() = value != null

        fun validatedPath(): String {
            val path = requireNotNull(value) { "PACKAGE_PATH_MISSING" }
            check(pattern.matches(path)) { "PACKAGE_PATH_INVALID" }
            return path
        }

        companion object {
            val pattern = Regex("/data/app/[A-Za-z0-9._~+=/-]{1,512}/base\\.apk")
        }
    }

    private data class ProcessResult(
        val exitCode: Int,
        val stdout: ByteArray,
        val stderr: ByteArray,
    )
}

internal data class ProbeOutput(val fields: Map<String, String>, val interceptorReentryCount: Int) {
    fun isValid(expectedGenerateCount: Int, expectedPhase: String): Boolean =
        fields["PROVEN"] == "true" &&
            fields["STATE_SEQUENCE"] ==
                "IDENTITY_CREATED,PUBLIC_TRUST_STAGED,PROFILE_STAGED,LISTENER_READY,TLS_PROVED,ACTIVE" &&
            fields["PRIVATE_KEY_ENCODED_NULL"] == "true" &&
            fields["INSIDE_SECURITY_HARDWARE"] == "true" &&
            fields["TEE_SECURITY_LEVEL"] == "true" &&
            fields["EC_P256"] == "true" &&
            fields["TLS_PROTOCOL"] == "TLSv1.3" &&
            fields["CLIENT_CERT_REQUIRED"] == "true" &&
            fields["PINNED_PEER"] == "true" &&
            fields["CANDIDATE_LOCAL_GENERATE_COUNT"] == expectedGenerateCount.toString() &&
            fields["WATCHDOG_TIMED_OUT"] == "false" &&
            fields["REBOOT_PHASE"] == expectedPhase &&
            interceptorReentryCount == 0

    fun failure(): String =
        fields["ERROR_CODE"]
            ?: when {
                interceptorReentryCount != 0 -> "INTERCEPTOR_REENTRY"
                else -> "ROOT_ASSERTION_FAILED"
            }

    companion object {
        fun parse(raw: String, interceptorReentryCount: Int): ProbeOutput {
            val fields =
                raw.lineSequence()
                    .mapNotNull { line ->
                        val separator = line.indexOf('=')
                        if (separator <= 0) null
                        else line.substring(0, separator) to line.substring(separator + 1)
                    }
                    .toMap()
            return ProbeOutput(fields, interceptorReentryCount)
        }
    }
}
