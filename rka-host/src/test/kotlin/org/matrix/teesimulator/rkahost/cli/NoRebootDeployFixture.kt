package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

internal class Fixture(private val mutation: FixtureMutation? = null) : java.io.Closeable {
    private val root = Files.createTempDirectory("no-reboot-deploy-")
    private val log = root.resolve("adb.log")
    private val pair = root.resolve("device-pair.json")
    private val zip = root.resolve("release.zip")
    private val evidence = root.resolve("evidence.json")
    private val adb = root.resolve("adb")
    private val tools = root.resolve("tools")
    internal val devices = root.resolve("devices")

    init {
        Files.writeString(
            pair,
            """{"candidate_serial":"CANDIDATE_B","donor_serial":"DONOR_A","profile_sha256":"${"a".repeat(64)}","schema_version":1}""" +
                "\n",
        )
        Files.writeString(root.resolve("device-pair.lock"), "")
        val encoder = Base64.getUrlEncoder().withoutPadding()
        Files.writeString(
            root.resolve("device-pair.env"),
            "RKA_DEVICE_PAIR_VERSION=1\n" +
                "RKA_DONOR_SERIAL_B64=${encoder.encodeToString("DONOR_A".toByteArray())}\n" +
                "RKA_CANDIDATE_SERIAL_B64=${encoder.encodeToString("CANDIDATE_B".toByteArray())}\n" +
                "RKA_PROFILE_SHA256=${"a".repeat(64)}\n",
        )
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        listOf("device-pair.json", "device-pair.env", "device-pair.lock").forEach {
            Files.setPosixFilePermissions(
                root.resolve(it),
                PosixFilePermissions.fromString("rw-------"),
            )
        }
        val archiveRoot = root.resolve("archive")
        Files.createDirectories(archiveRoot.resolve("META-INF"))
        Files.createDirectories(archiveRoot.resolve("webroot"))
        Files.writeString(archiveRoot.resolve("module.prop"), "id=tricky_store\nversion=fixture\n")
        Files.writeString(archiveRoot.resolve("rka-runtime.manifest"), "version=1\n")
        Files.writeString(archiveRoot.resolve("rka-sidecar"), "#!/bin/sh\nexit 0\n")
        Files.writeString(archiveRoot.resolve("sepolicy.probes"), "")
        Files.writeString(archiveRoot.resolve("sepolicy.rule"), "")
        Files.writeString(archiveRoot.resolve("webroot/index.html"), "fixture\n")
        Files.writeString(
            archiveRoot.resolve("rka-control.sh"),
            """#!/bin/sh
state=/data/adb/teesimulator-rka
case "${'$'}{1-}" in
  initialize) mkdir -p "${'$'}state/profiles"; printf 'version=1\nrole=FIXTURE\nprofile_epoch=7\n' > "${'$'}state/profiles/active.conf" ;;
esac
exit 0
""",
        )
        Files.writeString(archiveRoot.resolve("rka-supervisor.sh"), fixtureSupervisor)
        listOf("rka-control.sh", "rka-sidecar", "rka-supervisor.sh").forEach {
            Files.setPosixFilePermissions(
                archiveRoot.resolve(it),
                PosixFilePermissions.fromString("rwxr-xr-x"),
            )
        }
        val manifest =
            ProcessBuilder("bash", "-c", fixtureManifestCommand)
                .directory(archiveRoot.toFile())
                .start()
        check(manifest.waitFor() == 0)
        val zipped =
            ProcessBuilder("zip", "-qr", zip.toString(), ".")
                .directory(archiveRoot.toFile())
                .start()
        check(zipped.waitFor() == 0)
        val projectRoot = Path.of(System.getProperty("user.dir")).parent
        val sourceSha =
            ProcessBuilder("git", "rev-parse", "HEAD")
                .directory(projectRoot.toFile())
                .start()
                .let { process ->
                    val value = process.inputStream.bufferedReader().readText().trim()
                    check(process.waitFor() == 0)
                    value
                }
        Files.writeString(Path.of("${zip}.source-sha"), "$sourceSha\n")
        Files.writeString(adb, checkNotNull(javaClass.getResource("/rka-fake-adb.sh")).readText())
        Files.setPosixFilePermissions(adb, PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(devices)
        Files.createDirectory(tools)
        tools.resolve("git").also {
            Files.writeString(it, fixtureGit)
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
    }

    fun run(network: String = "direct-auto"): DeployResult =
        execute(network, sealedDescriptor = true, activeMutation = mutation)

    private fun execute(
        network: String,
        sealedDescriptor: Boolean,
        activeMutation: FixtureMutation?,
    ): DeployResult {
        val projectRoot = Path.of(System.getProperty("user.dir")).parent
        val script = projectRoot.resolve("scripts/rka-deploy.sh")
        val deploy =
            "\"$script\" --pair-fd-env RKA_DEVICE_PAIR_FD --zip \"$zip\" --network \"$network\" --no-reboot --evidence \"$evidence\""
        val command =
            if (sealedDescriptor) {
                "exec \"${projectRoot.resolve("scripts/rka-with-device-pair.sh")}\" --pair \"$pair\" -- $deploy"
            } else {
                "exec 3<\"$pair\"; export RKA_DEVICE_PAIR_FD=3; exec $deploy"
            }
        val process =
            ProcessBuilder("bash", "-c", command)
                .directory(projectRoot.toFile())
                .apply {
                    environment()["RKA_DEPLOY_ADB"] = adb.toString()
                    environment()["RKA_FAKE_LOG"] = log.toString()
                    environment()["RKA_FAKE_DEVICE_ROOT"] = devices.toString()
                    environment()["PATH"] = "$tools:${environment()["PATH"]}"
                    applyFixtureMutation(environment(), activeMutation)
                }
                .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return DeployResult(process.waitFor(), stdout, stderr)
    }

    fun runWithOrdinaryPairDescriptor(): DeployResult =
        execute("direct-auto", sealedDescriptor = false, activeMutation = null)

    fun runWithMismatchedProbe(): DeployResult =
        execute(
            "direct-auto",
            sealedDescriptor = true,
            activeMutation = FixtureMutation.MISMATCH_CANDIDATE_PIN,
        )

    fun runWithMutation(value: FixtureMutation): DeployResult =
        execute("direct-auto", sealedDescriptor = true, activeMutation = value)

    fun activeModuleBytes(): ByteArray =
        Files.readAllBytes(
            devices.resolve("DONOR_A/root/data/adb/modules/tricky_store/module.prop")
        )

    fun donorModuleSnapshot(): ModuleSnapshot {
        val module = devices.resolve("DONOR_A/root/data/adb/modules/tricky_store/module.prop")
        return ModuleSnapshot(
            Files.readAllBytes(module),
            Files.getPosixFilePermissions(module),
            Files.getLastModifiedTime(module).toMillis(),
        )
    }

    fun donorBindPresent(): Boolean =
        Files.isRegularFile(devices.resolve("DONOR_A/root/data/adb/teesimulator-rka/.bound"))

    fun donorRuntimeRunning(): Boolean =
        Files.readString(
                devices.resolve("DONOR_A/root/data/adb/teesimulator-rka/run/supervisor.state")
            )
            .trim() == "RUNNING"

    fun rollbackDonorAgain(): DeployResult {
        val tx =
            trace()
                .last { it.startsWith("DONOR_A ") && " deploy " in " $it " }
                .substringAfter("deploy ")
                .substringBefore(' ')
        return runRemote("DONOR_A", listOf("rollback", tx, "DONOR"))
    }

    private fun runRemote(serial: String, arguments: List<String>): DeployResult {
        val projectRoot = Path.of(System.getProperty("user.dir")).parent
        val script = Files.readString(projectRoot.resolve("scripts/rka-deploy.sh"))
        val helper =
            script
                .substringAfter("remote_helper=\"\$(cat <<'REMOTE_HELPER'\n")
                .substringBefore("\nREMOTE_HELPER\n")
        val process =
            ProcessBuilder(
                    listOf(adb.toString(), "-s", serial, "shell", "su", "0", "sh", "-s", "--") +
                        arguments
                )
                .directory(projectRoot.toFile())
                .apply {
                    environment()["RKA_FAKE_LOG"] = log.toString()
                    environment()["RKA_FAKE_DEVICE_ROOT"] = devices.toString()
                }
                .start()
        process.outputStream.use { it.write(helper.toByteArray()) }
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return DeployResult(process.waitFor(), stdout, stderr)
    }

    fun runWithUnsealedMemfd(): DeployResult {
        val projectRoot = Path.of(System.getProperty("user.dir")).parent
        val script = projectRoot.resolve("scripts/rka-deploy.sh")
        val code =
            """import os,sys
fd=os.memfd_create("rka-device-pair", os.MFD_ALLOW_SEALING)
os.write(fd, open(sys.argv[1], "rb").read())
os.lseek(fd, 0, os.SEEK_SET)
os.dup2(fd, 3, inheritable=True)
os.environ["RKA_DEVICE_PAIR_FD"]="3"
os.execv(sys.argv[2], [sys.argv[2], "--pair-fd-env", "RKA_DEVICE_PAIR_FD", "--zip", sys.argv[3], "--network", "direct-auto", "--no-reboot", "--evidence", sys.argv[4]])
"""
        val process =
            ProcessBuilder(
                    "python3",
                    "-c",
                    code,
                    pair.toString(),
                    script.toString(),
                    zip.toString(),
                    evidence.toString(),
                )
                .directory(projectRoot.toFile())
                .apply {
                    environment()["RKA_DEPLOY_ADB"] = adb.toString()
                    environment()["RKA_FAKE_LOG"] = log.toString()
                }
                .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return DeployResult(process.waitFor(), stdout, stderr)
    }

    fun trace(): List<String> = if (Files.exists(log)) Files.readAllLines(log) else emptyList()

    fun redactedOrder(): String =
        trace().joinToString(",") { line ->
            val serial = line.substringBefore(' ')
            val command =
                when {
                    " push " in " $line " -> "push"
                    " mkdir -p " in line -> "prepare"
                    " -- " in line -> line.substringAfter(" -- ").substringBefore(' ')
                    else -> "unknown"
                }
            "$serial:$command"
        }

    override fun close() {
        root.toFile().deleteRecursively()
    }
}
