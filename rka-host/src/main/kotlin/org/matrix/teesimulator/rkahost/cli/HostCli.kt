package org.matrix.teesimulator.rkahost.cli

import java.io.FileDescriptor
import java.io.FileInputStream
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

    internal fun run(arguments: Array<String>, runtime: Path): Int =
        try {
            when {
                arguments.contentEquals(arrayOf("--help")) -> {
                    printHelp()
                    0
                }
                arguments.take(2) == listOf("device-pair", "bind") -> bind(arguments, runtime)
                arguments.firstOrNull() == "verify-physical" -> verify(arguments)
                arguments.firstOrNull() in physicalRoots -> physical(arguments)
                else -> throw HostCliException("COMMAND_INVALID")
            }
        } catch (failure: HostCliException) {
            System.err.println("RESULT=${failure.message}")
            2
        }

    private fun bind(arguments: Array<String>, runtime: Path): Int {
        val values = options(arguments.drop(2))
        if (values.keys != setOf("--donor", "--candidate", "--profile")) {
            throw HostCliException("ARGUMENT_INVALID")
        }
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
        if (values.keys != setOf("--manifest", "--artifact", "--source-sha", "--nonce")) {
            throw HostCliException("ARGUMENT_INVALID")
        }
        val artifact = Path.of(values.getValue("--artifact"))
        val digest = Hashes.sha256(Files.readAllBytes(artifact))
        PhysicalManifest.verify(
            Files.readString(Path.of(values.getValue("--manifest"))),
            values.getValue("--source-sha"),
            digest,
            values.getValue("--nonce"),
        )
        println("""{"artifact_sha256":"$digest","result":"PHYSICAL_VERIFIED"}""")
        return 0
    }

    private fun physical(arguments: Array<String>): Int {
        if (arguments.any { it == "--pair" || it.startsWith("--pair=") }) {
            throw HostCliException("PAIR_PATH_FORBIDDEN")
        }
        val snapshot = DevicePairFd.readOnce()
        println(
            """{"command":"${arguments.joinToString("-")}","pair_sha256":"${Hashes.sha256(snapshot.canonical().toByteArray())}","result":"READY","transport":"DIRECT"}"""
        )
        return 0
    }

    private fun options(arguments: List<String>): Map<String, String> {
        if (arguments.size % 2 != 0) throw HostCliException("ARGUMENT_INVALID")
        val pairs = arguments.chunked(2).map { it[0] to it[1] }
        if (
            pairs.any { !it.first.startsWith("--") } ||
                pairs.map { it.first }.distinct().size != pairs.size
        ) {
            throw HostCliException("ARGUMENT_INVALID")
        }
        return pairs.toMap()
    }

    private fun printHelp() {
        println(
            """
            Usage: rka-host <fixed-command>
              device-pair bind --donor SERIAL --candidate SERIAL --profile FILE
              sentinel start|assert-live [--scope donor]
              profile pair
              deploy-no-reboot
              snapshot capability|config
              lifecycle run
              recover-exact
              cleanup
              evidence manifest
              verify-physical --manifest FILE --artifact FILE --source-sha SHA --nonce NONCE
            """
                .trimIndent()
        )
    }
}

private object DevicePairFd {
    fun readOnce(): DevicePairSnapshot {
        if (System.getenv("RKA_DEVICE_PAIR_FD") != "3") throw HostCliException("PAIR_FD_MISSING")
        val target =
            try {
                Files.readSymbolicLink(Path.of("/proc/self/fd/3")).toString()
            } catch (_: Exception) {
                throw HostCliException("PAIR_FD_INVALID")
            }
        if (!target.startsWith("/memfd:rka-device-pair")) throw HostCliException("PAIR_FD_UNSEALED")
        val constructor =
            FileDescriptor::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        if (!constructor.trySetAccessible()) throw HostCliException("PAIR_FD_INVALID")
        val descriptor = constructor.newInstance(3)
        val raw = FileInputStream(descriptor).use { it.readBytes().toString(Charsets.UTF_8) }
        return DevicePairSnapshot.parse(raw)
    }
}
