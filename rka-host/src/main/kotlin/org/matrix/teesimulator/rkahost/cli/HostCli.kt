package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

object HostCli {
    private val physicalRoots =
        setOf(
            "sentinel",
            "profile",
            "deploy-no-reboot",
            "snapshot",
            "lifecycle",
            "recover-exact",
            "cleanup",
            "evidence",
        )

    @JvmStatic
    fun main(arguments: Array<String>) {
        val runtime = System.getenv("RKA_RUNTIME_DIR")?.let(Path::of) ?: Path.of(".omo", "runtime")
        exitProcess(run(arguments, runtime))
    }

    internal fun run(
        arguments: Array<String>,
        runtime: Path,
        runner: HostCommandRunner = ProcessHostCommandRunner(),
    ): Int =
        try {
            when {
                arguments.contentEquals(arrayOf("--help")) -> {
                    printHelp()
                    0
                }
                arguments.take(2) == listOf("device-pair", "bind") -> bind(arguments, runtime)
                arguments.firstOrNull() == "verify-physical" -> verify(arguments)
                arguments.firstOrNull() == "trace-adb" -> traceAdb(arguments.drop(1), runtime)
                arguments.take(2) == listOf("sentinel", "cleanup") ->
                    cleanupTrace(arguments, runtime)
                arguments.firstOrNull() in physicalRoots -> physical(arguments, runner, runtime)
                else -> throw HostCliException("COMMAND_INVALID")
            }
        } catch (failure: HostCliException) {
            System.err.println("RESULT=${failure.message}")
            2
        } catch (_: Exception) {
            System.err.println("RESULT=HOST_OPERATION_FAILED")
            2
        }

    private fun bind(arguments: Array<String>, runtime: Path): Int {
        val arguments = arguments.drop(2)
        if (arguments.size % 2 != 0) invalid()
        val pairs = arguments.chunked(2).map { it[0] to it[1] }
        if (
            pairs.any { it.first !in setOf("--donor", "--candidate", "--profile") } ||
                pairs.any { it.second.isBlank() } ||
                pairs.count { it.first == "--donor" } != 1
        ) {
            invalid()
        }
        val candidates = pairs.filter { it.first == "--candidate" }.map(Pair<String, String>::second)
        val profiles = pairs.filter { it.first == "--profile" }.map(Pair<String, String>::second)
        if (candidates.isEmpty() || candidates.size != profiles.size) invalid()
        val snapshot =
            DevicePairStore(runtime)
                .bind(
                    pairs.single { it.first == "--donor" }.second,
                    candidates.zip(profiles.map(Path::of)),
                )
        println(
            """{"candidate_count":${snapshot.candidates.size},"donor_serial_sha256":"${Hashes.sha256(snapshot.donor.value.toByteArray())}","result":"BOUND"}"""
        )
        return 0
    }

    private fun verify(arguments: Array<String>): Int {
        val values = options(arguments.drop(1))
        requireKeys(
            values,
            setOf("--manifest", "--baseline", "--artifact", "--source-sha", "--nonce"),
        )
        val artifactDigest = digest(values.getValue("--artifact"))
        val baseline = BaselineStore.read(Path.of(values.getValue("--baseline")))
        val currentBinding = PairBinding.from(NativePairDescriptor.readOnce())
        if (baseline.binding != currentBinding) throw HostCliException("PAIR_BINDING_MISMATCH")
        PhysicalReceipt.verify(
            EvidenceStore.read(Path.of(values.getValue("--manifest"))),
            Path.of(values.getValue("--baseline")),
            baseline,
            currentBinding,
            values.getValue("--source-sha"),
            artifactDigest,
            values.getValue("--nonce"),
        )
        println("""{"artifact_sha256":"$artifactDigest","result":"PHYSICAL_VERIFIED"}""")
        return 0
    }

    private fun physical(arguments: Array<String>, runner: HostCommandRunner, runtime: Path): Int {
        if (
            arguments.any {
                it in setOf("--pair", "--donor", "--candidate", "--serial") ||
                    it.startsWith("--pair=") ||
                    it.startsWith("--donor=") ||
                    it.startsWith("--candidate=") ||
                    it.startsWith("--serial=")
            }
        ) {
            throw HostCliException("PAIR_PATH_FORBIDDEN")
        }
        val snapshot = NativePairDescriptor.readOnce()
        val binding = PairBinding.from(snapshot)
        val starting = arguments.take(2) == listOf("sentinel", "start")
        val context = if (starting) null else TraceContextStore.read(runtime, binding)
        val host =
            HostOrchestrator(
                snapshot,
                runner,
                context?.let { PersistentAdbTrace.open(it.first, it.second) },
            )
        val result =
            when (arguments.first()) {
                "sentinel" -> sentinel(arguments, host, runtime)
                "profile" -> {
                    if (!arguments.contentEquals(arrayOf("profile", "pair"))) invalid()
                    host.profilePair()
                    "PROFILED"
                }
                "deploy-no-reboot" -> {
                    val values = options(arguments.drop(1))
                    requireKeys(values, setOf("--zip"))
                    host.deployNoReboot(values.getValue("--zip"))
                    "DEPLOYED_NO_REBOOT"
                }
                "snapshot" -> {
                    if (arguments.size != 2) invalid()
                    host.snapshot(arguments[1])
                    "SNAPSHOT_CAPTURED"
                }
                "lifecycle" -> {
                    if (arguments.size != 2) invalid()
                    host.lifecycle(arguments[1])
                    "LIFECYCLE_${arguments[1].uppercase()}"
                }
                "recover-exact" -> {
                    val values = options(arguments.drop(1))
                    requireKeys(values, setOf("--role", "--service"))
                    host.recoverExact(values.getValue("--role"), values.getValue("--service"))
                    "RECOVERED_EXACT"
                }
                "cleanup" -> {
                    if (arguments.size != 1) invalid()
                    host.cleanup()
                    "CLEANED"
                }
                "evidence" -> evidence(arguments, host)
                else -> invalid()
            }
        println(
            """{"pair_sha256":"${Hashes.sha256(snapshot.canonical().toByteArray())}","result":"$result","transport":"DIRECT"}"""
        )
        return 0
    }

    private fun sentinel(arguments: Array<String>, host: HostOrchestrator, runtime: Path): String {
        if (arguments.size < 2) invalid()
        val values = options(arguments.drop(2))
        return when (arguments[1]) {
            "start" -> {
                if (
                    values.keys != setOf("--baseline", "--nonce") &&
                        values.keys != setOf("--baseline", "--nonce", "--scope")
                ) {
                    invalid()
                }
                if (values.values.any(String::isBlank)) invalid()
                val baselinePath = Path.of(values.getValue("--baseline"))
                val baseline =
                    host.sentinelStart(
                        baselinePath,
                        values.getValue("--nonce"),
                        when (values["--scope"] ?: "pair") {
                            "pair" -> SentinelScope.PAIR
                            "donor" -> SentinelScope.DONOR
                            else -> invalid()
                        },
                        DeploySurfaceBinding.fromEnvironment(),
                    )
                TraceContextStore.write(runtime, baselinePath, baseline)
                "SENTINEL_STARTED"
            }
            "sample" -> {
                requireKeys(values, setOf("--baseline"))
                host.sentinelSample(Path.of(values.getValue("--baseline")))
                "SENTINEL_SAMPLED"
            }
            "finish" -> {
                requireKeys(values, setOf("--baseline"))
                host.sentinelFinish(Path.of(values.getValue("--baseline")))
                "SENTINEL_FINISHED"
            }
            "verify" -> {
                requireKeys(values, setOf("--baseline"))
                host.sentinelVerify(Path.of(values.getValue("--baseline")))
                "SENTINEL_VERIFIED"
            }
            "assert-live" -> {
                requireKeys(values, setOf("--baseline"))
                host.sentinelAssertLive(Path.of(values.getValue("--baseline")))
                "SENTINEL_LIVE"
            }
            "stop" -> {
                requireKeys(values, setOf("--baseline"))
                val baselinePath = Path.of(values.getValue("--baseline"))
                host.sentinelStop(baselinePath)
                "SENTINEL_STOPPED"
            }
            else -> invalid()
        }
    }

    private fun evidence(arguments: Array<String>, host: HostOrchestrator): String {
        if (arguments.getOrNull(1) != "manifest") invalid()
        val values = options(arguments.drop(2))
        requireKeys(
            values,
            setOf("--baseline", "--artifact", "--source-sha", "--nonce", "--output"),
        )
        val baseline = BaselineStore.read(Path.of(values.getValue("--baseline")))
        if (baseline.nonce != values.getValue("--nonce")) throw HostCliException("NONCE_STALE")
        val sample = host.terminalSample()
        val receipt =
            PhysicalReceipt.create(
                baseline,
                sample.donorBootId,
                sample.candidateBootId,
                sample.donorMillis,
                sample.candidateMillis,
                values.getValue("--source-sha"),
                digest(values.getValue("--artifact")),
                host.persistentTrace(),
            )
        EvidenceStore.write(Path.of(values.getValue("--output")), receipt)
        if (EvidenceStore.read(Path.of(values.getValue("--output"))) != receipt) {
            throw HostCliException("EVIDENCE_PAIR_MISMATCH")
        }
        host.markReceipted(receipt)
        return "EVIDENCE_WRITTEN"
    }

    private fun cleanupTrace(arguments: Array<String>, runtime: Path): Int {
        val values = options(arguments.drop(2))
        requireKeys(values, setOf("--baseline"))
        val path = Path.of(values.getValue("--baseline"))
        val binding = PairBinding.from(NativePairDescriptor.readOnce())
        val baseline =
            if (Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                BaselineStore.read(path).also {
                    if (it.binding != binding) throw HostCliException("PAIR_BINDING_MISMATCH")
                }
            } else {
                null
            }
        PersistentAdbTrace.cleanupAfterReceipt(path, baseline, runtime)
        println("""{"result":"SENTINEL_CLEANED"}""")
        return 0
    }

    private fun digest(path: String): String =
        try {
            Hashes.sha256(Files.readAllBytes(Path.of(path)))
        } catch (_: Exception) {
            throw HostCliException("ARTIFACT_INVALID")
        }

    private fun traceAdb(arguments: List<String>, runtime: Path): Int {
        if (arguments.isEmpty()) invalid()
        val snapshot = NativePairDescriptor.readOnce()
        val context =
            TraceContextStore.read(runtime, PairBinding.from(snapshot))
                ?: throw HostCliException("COMMAND_TRACE_MISSING")
        val executable = System.getenv("RKA_TRACE_REAL_ADB")?.takeIf(String::isNotBlank) ?: "adb"
        val stdin = System.`in`.readNBytes(MAX_TRACE_ADB_STDIN_BYTES + 1)
        if (stdin.size > MAX_TRACE_ADB_STDIN_BYTES) {
            throw HostCliException("ADB_STDIN_INVALID")
        }
        val result =
            TracedHostCommandRunner(
                    ProcessHostCommandRunner(executable, stdin),
                    PersistentAdbTrace.open(context.first, context.second),
                )
                .run(listOf("adb") + arguments)
        print(result.stdout)
        System.err.print(result.stderr)
        return result.exitCode
    }

    private fun options(arguments: List<String>): Map<String, String> {
        if (arguments.size % 2 != 0) invalid()
        val pairs = arguments.chunked(2).map { it[0] to it[1] }
        if (
            pairs.any { !it.first.startsWith("--") } ||
                pairs.map { it.first }.distinct().size != pairs.size
        ) {
            invalid()
        }
        return pairs.toMap()
    }

    private fun requireKeys(values: Map<String, String>, required: Set<String>) {
        if (values.keys != required || values.values.any(String::isBlank)) invalid()
    }

    private fun invalid(): Nothing = throw HostCliException("ARGUMENT_INVALID")

    private fun printHelp() {
        println(
            """
            Usage: rka-host <fixed-command>
              device-pair bind --donor SERIAL --candidate SERIAL --profile FILE
              sentinel start --baseline FILE --nonce NONCE [--scope pair|donor]
              sentinel sample|finish|verify|assert-live|stop|cleanup --baseline FILE
              profile pair
              deploy-no-reboot --zip FILE
              snapshot capability|config
              lifecycle status|start|stop
              recover-exact --role donor|candidate --service keystore2|rkpd
              cleanup
              evidence manifest --baseline FILE --artifact FILE --source-sha SHA --nonce NONCE --output FILE
              verify-physical --manifest FILE --baseline FILE --artifact FILE --source-sha SHA --nonce NONCE
              trace-adb <adb arguments supplied by the deploy adapter>
            """
                .trimIndent()
        )
    }

    private const val MAX_TRACE_ADB_STDIN_BYTES = 65_536
}
