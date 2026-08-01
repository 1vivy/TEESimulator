package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistentTraceMultiProcessIntegrationTest {
    @Test
    fun separateInstalledCliProcessesContendOnFilesystemLock() {
        val project = Path.of(System.getProperty("user.dir")).parent
        val installed = project.resolve("rka-host/build/install/rka-host/bin/rka-host")
        assertTrue("installDist launcher missing", Files.isExecutable(installed))
        val runtime = Files.createTempDirectory("trace-cross-process-")
        Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwx------"))
        val donor = "DONOR_SERIAL"
        val candidate = "CANDIDATE_SERIAL"
        val pair = pair(runtime, donor, candidate)
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
        val tools = Files.createDirectory(runtime.resolve("tools"))
        val fakeAdb = tools.resolve("adb")
        Files.writeString(fakeAdb, "#!/bin/sh\nsleep 0.2\nprintf '%s\\n' \"${'$'}*\"\n")
        Files.setPosixFilePermissions(fakeAdb, PosixFilePermissions.fromString("rwx------"))
        val environment = mapOf("PATH" to "$tools:${System.getenv("PATH")}")

        val first =
            startInstalled(
                runtime,
                installed,
                environment,
                "trace-adb",
                "-s",
                donor,
                "shell",
                "getprop",
                "property.one",
            )
        val second =
            startInstalled(
                runtime,
                installed,
                environment,
                "trace-adb",
                "-s",
                candidate,
                "shell",
                "getprop",
                "property.two",
            )
        first.outputStream.close()
        second.outputStream.close()

        assertTrue(first.waitFor(10, TimeUnit.SECONDS))
        assertTrue(second.waitFor(10, TimeUnit.SECONDS))
        assertEquals(first.errorStream.bufferedReader().readText(), 0, first.exitValue())
        assertEquals(second.errorStream.bufferedReader().readText(), 0, second.exitValue())
        val completed = PersistentAdbTrace.open(baselinePath, baseline).validateClean()
        val lines =
            completed.canonical
                .toString(Charsets.UTF_8)
                .lineSequence()
                .drop(1)
                .filter(String::isNotEmpty)
                .toList()

        assertEquals(4, completed.binding.eventCount)
        assertEquals(listOf("1", "2", "3", "4"), lines.map { it.substringBefore('|') })
        assertEquals(2, lines.count { "|START|" in it })
        assertEquals(2, lines.count { "|EXIT_OK|0|" in it })
        assertFalse(completed.canonical.toString(Charsets.UTF_8).contains(donor))
        assertFalse(completed.canonical.toString(Charsets.UTF_8).contains(candidate))
    }

    private fun pair(runtime: Path, donor: String, candidate: String): DevicePairSnapshot {
        val snapshot =
            DevicePairSnapshot(
                BoundSerial.parse(donor),
                BoundSerial.parse(candidate),
                "d".repeat(64),
            )
        val donorB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(donor.toByteArray())
        val candidateB64 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(candidate.toByteArray())
        Files.writeString(runtime.resolve("device-pair.json"), snapshot.canonical())
        Files.writeString(
            runtime.resolve("device-pair.env"),
            "RKA_DEVICE_PAIR_VERSION=1\nRKA_DONOR_SERIAL_B64=$donorB64\nRKA_CANDIDATE_SERIAL_B64=$candidateB64\nRKA_PROFILE_SHA256=${"d".repeat(64)}\n",
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

    private fun startInstalled(
        runtime: Path,
        installed: Path,
        environment: Map<String, String>,
        vararg arguments: String,
    ): Process =
        ProcessBuilder(
                listOf(
                    "python3",
                    "-c",
                    INSTALLED_LAUNCHER,
                    installed.toString(),
                    runtime.resolve("device-pair.json").toString(),
                ) + arguments
            )
            .apply {
                environment().putAll(environment)
                environment()["RKA_RUNTIME_DIR"] = runtime.toString()
                environment()["RKA_DEVICE_PAIR_FD"] = "3"
            }
            .start()

    private companion object {
        val INSTALLED_LAUNCHER =
            """
            import fcntl, json, os, sys
            host, pair_path, *args = sys.argv[1:]
            raw = open(pair_path, "rb").read()
            fd = os.memfd_create("rka-device-pair", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.write(fd, raw)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
            readonly = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
            os.dup2(readonly, 3, inheritable=True)
            os.execve(host, [host] + args, os.environ)
            """
                .trimIndent()
    }
}
