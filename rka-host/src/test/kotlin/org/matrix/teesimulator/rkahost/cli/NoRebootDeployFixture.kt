package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

internal class Fixture(
    private val mutation: FixtureMutation? = null,
    private val kernelProfile: KernelProfile = KernelProfile.LEGACY,
) : java.io.Closeable {
    private val root = Files.createTempDirectory("no-reboot-deploy-")
    private val log = root.resolve("adb.log")
    private val pair = root.resolve("device-pair.json")
    private val zip = root.resolve("release.zip")
    private val evidence = root.resolve("evidence.json")
    private val adb = root.resolve("adb")
    private val tools = root.resolve("tools")
    internal val devices = root.resolve("devices")
    private val tlsServers = FixtureTlsServers(root.resolve("tls"))

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
        Files.writeString(
            archiveRoot.resolve("rka-sidecar"),
            """#!/bin/sh
if [ "${'$'}{1-}" = manager-appid ]; then
  if [ "${'$'}{RKA_FAKE_NEXT_MUTATION-}" = appid-zero ]; then printf '0\n'; exit 0; fi
  if [ "${'$'}{RKA_FAKE_NEXT_MUTATION-}" = appid-error ]; then exit 2; fi
  if [ "${'$'}{RKA_FAKE_NEXT_MUTATION-}" = boot-drift ]; then : > /data/adb/teesimulator-rka/.boot-drift; fi
  case "${'$'}{RKA_FAKE_SERIAL-}" in DONOR_A) printf '10123\n' ;; CANDIDATE_B) printf '10124\n' ;; *) exit 2 ;; esac
  exit 0
fi
if [ "${'$'}{1-}" = direct-identity ]; then
  mkdir -p "${'$'}RKA_STATE_ROOT/secrets" "${'$'}RKA_STATE_ROOT/trust"
  cp "/tls-fixture/${'$'}RKA_FAKE_SERIAL/server.key" "${'$'}RKA_STATE_ROOT/secrets/transport.key"
  cp "/tls-fixture/${'$'}RKA_FAKE_SERIAL/server.pem" "${'$'}RKA_STATE_ROOT/trust/transport-self.pem"
  cp "/tls-fixture/${'$'}RKA_FAKE_SERIAL/server.pem" "${'$'}RKA_STATE_ROOT/trust/transport-trust.pem"
  cp "/tls-fixture/${'$'}RKA_FAKE_SERIAL/server.pin" "${'$'}RKA_STATE_ROOT/trust/transport.pin"
  printf 'version=1\nspki_sha256=%s\n' "${'$'}(cat "/tls-fixture/${'$'}RKA_FAKE_SERIAL/server.pin")" > "${'$'}RKA_STATE_ROOT/trust/transport-identity.commit"
  chmod 600 "${'$'}RKA_STATE_ROOT/secrets/transport.key" "${'$'}RKA_STATE_ROOT/trust/transport-self.pem" "${'$'}RKA_STATE_ROOT/trust/transport-trust.pem" "${'$'}RKA_STATE_ROOT/trust/transport.pin" "${'$'}RKA_STATE_ROOT/trust/transport-identity.commit"
  printf 'RESULT=IDENTITY spki_sha256=%s\n' "${'$'}(cat "${'$'}RKA_STATE_ROOT/trust/transport.pin")"
  exit 0
fi
if [ "${'$'}{1-}" = direct-probe ]; then
  [ "${'$'}{RKA_FAKE_PROBE_STATUS-}" != unavailable ] || exit 2
  if [ "${'$'}{RKA_FAKE_PROBE_STATUS-}" = stale ]; then
    sed -i 's/^profile_epoch=7${'$'}/profile_epoch=6/' "${'$'}RKA_PROFILE_PATH"
  fi
  [ "${'$'}{RKA_FAKE_TLS_PROTOCOL-}" != TLS1.2 ] || exit 2
  [ "${'$'}{RKA_FAKE_MISMATCH_PIN-false}" != true ] || exit 2
  profile_sha=${'$'}(sha256sum "${'$'}RKA_PROFILE_PATH" | awk '{print ${'$'}1}')
  epoch=${'$'}(sed -n '3s/^profile_epoch=//p' "${'$'}RKA_PROFILE_PATH")
  [ "${'$'}epoch" = "${'$'}RKA_EXPECTED_PROFILE_EPOCH" ] || exit 2
  pin=${'$'}(sed -n '5s/^peer_spki_sha256=//p' "${'$'}RKA_PROFILE_PATH")
  pin_sha=${'$'}(printf %s "${'$'}pin" | xxd -r -p | sha256sum | awk '{print ${'$'}1}')
  printf 'version=1\nprotocol=TLSv1.3\nprofile_sha256=%s\nprofile_epoch=%s\npeer_pin_sha256=%s\ntransport=DIRECT\n' "${'$'}profile_sha" "${'$'}epoch" "${'$'}pin_sha" > "${'$'}RKA_DIRECT_PROBE_RECEIPT_PATH"
  chmod 600 "${'$'}RKA_DIRECT_PROBE_RECEIPT_PATH"
  printf 'RESULT=DIRECT protocol=TLSv1.3 profile_sha256=%s\n' "${'$'}profile_sha"
  exit 0
fi
exit 0
""",
        )
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
            Files.writeString(it, fixtureGit(sourceSha))
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
        return tlsServers.withServers(activeMutation) {
            val process =
                ProcessBuilder("bash", "-c", command)
                    .directory(projectRoot.toFile())
                    .apply {
                        environment()["RKA_DEPLOY_ADB"] = adb.toString()
                        environment()["RKA_FAKE_LOG"] = log.toString()
                        environment()["RKA_FAKE_DEVICE_ROOT"] = devices.toString()
                        environment()["RKA_FAKE_TLS_ROOT"] = root.resolve("tls").toString()
                        environment()["RKA_FAKE_KSU_PROFILE"] = kernelProfile.fixtureName
                        environment()["RKA_FAKE_FIRST_INSTALL"] =
                            kernelProfile.firstInstall.toString()
                        environment()["RKA_FAKE_SYSTEM_OPENSSL"] =
                            kernelProfile.systemOpenSsl.toString()
                        environment()["PATH"] = "$tools:${environment()["PATH"]}"
                        applyFixtureMutation(environment(), activeMutation)
                    }
                    .start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            DeployResult(process.waitFor(), stdout, stderr)
        }
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

    fun tlsServersStopped(): Boolean = tlsServers.allStopped()

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
                    environment()["RKA_FAKE_TLS_ROOT"] = root.resolve("tls").toString()
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

    fun probeArtifactsAbsent(): Boolean =
        listOf("DONOR_A", "CANDIDATE_B").all { serial ->
            val probes = devices.resolve(serial).resolve("root/data/adb/teesimulator-rka/probes")
            !Files.exists(probes) || Files.list(probes).use { it.findAny().isEmpty }
        }

    fun hasFirstInstallReceipts(): Boolean =
        listOf("DONOR_A", "CANDIDATE_B").all { serial ->
            val transaction = latestTransaction(serial)
            Files.readString(transaction.resolve("layout.before")).trim() ==
                "FIRST_INSTALL_ABSENT_LAYOUT" &&
                Files.isRegularFile(
                    devices
                        .resolve(serial)
                        .resolve("root/data/adb/teesimulator-rka/active-underlay/update")
                ) &&
                Files.isRegularFile(
                    devices
                        .resolve(serial)
                        .resolve("root/data/adb/modules_update/tricky_store/module.prop")
                )
        }

    fun firstInstallFacts(): String =
        listOf("DONOR_A", "CANDIDATE_B").joinToString(";") { serial ->
            val transaction = latestTransaction(serial)
            val adbRoot = devices.resolve(serial).resolve("root/data/adb")
            "$serial:layout=${Files.readString(transaction.resolve("layout.before")).trim()}," +
                "active=${Files.exists(adbRoot.resolve("teesimulator-rka/active-underlay/update"))}," +
                "pending=${Files.exists(adbRoot.resolve("modules_update/tricky_store/module.prop"))}"
        }

    fun moduleParentsAbsent(): Boolean =
        listOf("DONOR_A", "CANDIDATE_B").all { serial ->
            val adbRoot = devices.resolve(serial).resolve("root/data/adb")
            !Files.exists(adbRoot.resolve("modules")) &&
                !Files.exists(adbRoot.resolve("modules_update"))
        }

    fun hasKsuNextManagerSurfaceReceipts(): Boolean {
        val donor = latestTransaction("DONOR_A")
        val candidate = latestTransaction("CANDIDATE_B")
        val donorOwner = Files.readString(donor.resolve("webui-owner.receipt"))
        val candidateOwner = Files.readString(candidate.resolve("webui-owner.receipt"))
        val donorViews = Files.readAllLines(donor.resolve("mount-views.receipt"))
        val candidateViews = Files.readAllLines(candidate.resolve("mount-views.receipt"))
        val transaction = donor.fileName.toString()
        val donorAuthorization =
            Files.readString(
                devices
                    .resolve("DONOR_A/root/data/adb/teesimulator-rka/manager-authorizations")
                    .resolve(transaction)
            )
        return "surface=KSU_NEXT_MANAGER" in donorOwner &&
            "manager_process=com.rifsxd.ksunext" in donorOwner &&
            "binary_evidence=exact-observed-binary" in donorAuthorization &&
            "reference_evidence=reference-source" in donorAuthorization &&
            "surface=HEADLESS_AUTHORIZED_MANAGER" in candidateOwner &&
            "omitted_views=manager,webui" in candidateOwner &&
            donorViews.map { it.substringBefore('=') } ==
                listOf("init", "manager", "webui", "broker", "sidecar") &&
            candidateViews.map { it.substringBefore('=') } == listOf("init", "broker", "sidecar")
    }

    private fun latestTransaction(serial: String): Path {
        val transactions =
            devices.resolve(serial).resolve("root/data/adb/teesimulator-rka/deploy-transactions")
        return Files.list(transactions).use { it.findFirst().orElseThrow() }
    }

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
        tlsServers.close()
        root.toFile().deleteRecursively()
    }
}
