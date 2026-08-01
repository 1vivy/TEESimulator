package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistentTraceMultiProcessIntegrationTest {
    @Test
    fun standardWrapperDeployAdapterAndLaterHostProcessShareCompleteTrace() {
        val project = Path.of(System.getProperty("user.dir")).parent
        val runtime = Files.createTempDirectory("trace-multiprocess-")
        Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwx------"))
        val donor = "DONOR_SERIAL"
        val candidate = "CANDIDATE_SERIAL"
        val profile = "d".repeat(64)
        val pair = pair(runtime, donor, candidate, profile)
        val binding = PairBinding.from(pair)
        val baselinePath = runtime.resolve("baseline.json")
        val journal = PersistentAdbTrace.create(baselinePath, binding, "sentinel", "nonce")
        val initial = journal.validateClean().binding
        val baseline =
            SentinelBaseline(
                "sentinel",
                "nonce",
                binding,
                "donor-boot",
                "candidate-boot",
                1,
                1,
                commandTraceGenesisSha256 = initial.genesisSha256,
                commandTraceSessionId = initial.sessionId,
                commandTraceInitialHeadSha256 = initial.headSha256,
            )
        BaselineStore.create(baselinePath, baseline)
        TraceContextStore.write(runtime, baselinePath, baseline)
        val tools = runtime.resolve("tools")
        Files.createDirectory(tools)
        val host = executable(tools.resolve("rka-host"), hostLauncher())
        val fakeAdbScript =
            "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> \"\$RKA_FAKE_ADB_LOG\"\ncase \"\$*\" in *controlled-failure*) exit 19 ;; esac\n"
        val fakeAdb = executable(tools.resolve("fake-adb"), fakeAdbScript)
        executable(tools.resolve("adb"), fakeAdbScript)
        val deploy =
            executable(
                runtime.resolve("rka-deploy.sh"),
                "#!/bin/sh\nset -eu\n\"\$RKA_DEPLOY_ADB\" -s '$donor' shell getprop ro.build.version.release\n\"\$RKA_DEPLOY_ADB\" -s '$candidate' shell getprop controlled-failure || :\n",
            )
        val log = runtime.resolve("adb.log")
        val environment =
            mapOf(
                "PATH" to "$tools:${System.getenv("PATH")}",
                "RKA_DEPLOY_ADB" to fakeAdb.toString(),
                "RKA_FAKE_ADB_LOG" to log.toString(),
            )
        val deployResult = wrapper(project, runtime, deploy.toString(), environment)
        assertEquals(deployResult.stderr, 0, deployResult.exitCode)
        val later =
            wrapper(
                project,
                runtime,
                host.toString(),
                environment,
                "trace-adb",
                "-s",
                donor,
                "shell",
                "cat",
                "/proc/uptime",
            )
        assertEquals(later.stderr, 0, later.exitCode)
        val completed = PersistentAdbTrace.open(baselinePath, baseline).snapshotForReceipt()
        val receipt =
            PhysicalReceipt.create(
                baseline,
                "donor-boot",
                "candidate-boot",
                2,
                2,
                "a".repeat(40),
                "b".repeat(64),
                completed,
            )

        assertEquals(6, completed.binding.eventCount)
        assertTrue(completed.canonical.toString(Charsets.UTF_8).contains("EXIT_NONZERO|19|"))
        assertFalse(completed.canonical.toString(Charsets.UTF_8).contains(donor))
        assertTrue(receipt.contains("\"command_trace_event_count\":6"))
        println(
            "TRACE_EVENT_COUNT=${completed.binding.eventCount} TRACE_HEAD=${completed.binding.headSha256} " +
                "VERDICT=${completed.verdict} CONTROLLED_NONZERO=true RAW_SERIAL_PRESENT=false RECEIPT_VERIFIED=true"
        )
        assertEquals(
            "b".repeat(64),
            PhysicalReceipt.verify(
                receipt,
                baselinePath,
                baseline,
                binding,
                "a".repeat(40),
                "b".repeat(64),
                "nonce",
            ),
        )
    }

    private fun pair(
        runtime: Path,
        donor: String,
        candidate: String,
        profile: String,
    ): DevicePairSnapshot {
        val snapshot =
            DevicePairSnapshot(BoundSerial.parse(donor), BoundSerial.parse(candidate), profile)
        val donorB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(donor.toByteArray())
        val candidateB64 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(candidate.toByteArray())
        Files.writeString(runtime.resolve("device-pair.json"), snapshot.canonical())
        Files.writeString(
            runtime.resolve("device-pair.env"),
            "RKA_DEVICE_PAIR_VERSION=1\nRKA_DONOR_SERIAL_B64=$donorB64\nRKA_CANDIDATE_SERIAL_B64=$candidateB64\nRKA_PROFILE_SHA256=$profile\n",
        )
        Files.writeString(runtime.resolve("device-pair.lock"), "")
        listOf("device-pair.json", "device-pair.env", "device-pair.lock").forEach {
            Files.setPosixFilePermissions(
                runtime.resolve(it),
                PosixFilePermissions.fromString("rw-------"),
            )
        }
        return snapshot
    }

    private fun wrapper(
        project: Path,
        runtime: Path,
        command: String,
        environment: Map<String, String>,
        vararg arguments: String,
    ): HostCommandResult {
        val process =
            ProcessBuilder(
                    listOf(
                        project.resolve("scripts/rka-with-device-pair.sh").toString(),
                        "--pair",
                        runtime.resolve("device-pair.json").toString(),
                        "--",
                        command,
                    ) + arguments
                )
                .apply { environment().putAll(environment) }
                .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return HostCommandResult(process.waitFor(), stdout, stderr)
    }

    private fun hostLauncher(): String {
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val classpath = System.getProperty("java.class.path")
        return "#!/bin/sh\nexec '$java' --enable-native-access=ALL-UNNAMED -cp '$classpath' ${HostCli::class.java.name} \"\$@\"\n"
    }

    private fun executable(path: Path, value: String): Path {
        Files.writeString(path, value)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path
    }
}
