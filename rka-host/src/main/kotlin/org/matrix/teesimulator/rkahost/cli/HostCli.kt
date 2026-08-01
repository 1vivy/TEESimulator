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
                arguments.firstOrNull() in physicalRoots -> physical(arguments, runner)
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
        val values = options(arguments.drop(2))
        requireKeys(values, setOf("--donor", "--candidate", "--profile"))
        val snapshot =
            DevicePairStore(runtime)
                .bind(
                    values.getValue("--donor"),
                    values.getValue("--candidate"),
                    Path.of(values.getValue("--profile")),
                )
        println(
            """{"candidate_serial_sha256":"${Hashes.sha256(snapshot.candidate.value.toByteArray())}","donor_serial_sha256":"${Hashes.sha256(snapshot.donor.value.toByteArray())}","result":"BOUND"}"""
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
            baseline,
            currentBinding,
            values.getValue("--source-sha"),
            artifactDigest,
            values.getValue("--nonce"),
        )
        println("""{"artifact_sha256":"$artifactDigest","result":"PHYSICAL_VERIFIED"}""")
        return 0
    }

    private fun physical(arguments: Array<String>, runner: HostCommandRunner): Int {
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
        val host = HostOrchestrator(snapshot, runner)
        val result =
            when (arguments.first()) {
                "sentinel" -> sentinel(arguments, host)
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

    private fun sentinel(arguments: Array<String>, host: HostOrchestrator): String {
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
                host.sentinelStart(
                    Path.of(values.getValue("--baseline")),
                    values.getValue("--nonce"),
                    when (values["--scope"] ?: "pair") {
                        "pair" -> SentinelScope.PAIR
                        "donor" -> SentinelScope.DONOR
                        else -> invalid()
                    },
                )
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
                host.sentinelStop(Path.of(values.getValue("--baseline")))
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
        val sample = host.sentinelFinish(Path.of(values.getValue("--baseline")))
        val receipt =
            PhysicalReceipt.create(
                baseline,
                sample.donorBootId,
                sample.candidateBootId,
                sample.donorMillis,
                sample.candidateMillis,
                values.getValue("--source-sha"),
                digest(values.getValue("--artifact")),
                host.trace(),
            )
        EvidenceStore.write(Path.of(values.getValue("--output")), receipt)
        return "EVIDENCE_WRITTEN"
    }

    private fun digest(path: String): String =
        try {
            Hashes.sha256(Files.readAllBytes(Path.of(path)))
        } catch (_: Exception) {
            throw HostCliException("ARTIFACT_INVALID")
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
              sentinel sample|finish|verify|assert-live|stop --baseline FILE
              profile pair
              deploy-no-reboot --zip FILE
              snapshot capability|config
              lifecycle status|start|stop
              recover-exact --role donor|candidate --service keystore2|rkpd
              cleanup
              evidence manifest --baseline FILE --artifact FILE --source-sha SHA --nonce NONCE --output FILE
              verify-physical --manifest FILE --baseline FILE --artifact FILE --source-sha SHA --nonce NONCE
            """
                .trimIndent()
        )
    }
}
