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

class PairWrapperIntegrationTest {
    @Test
    fun standardWrapperCanonicalizesLegacyPairAndReachesSentinelWithoutJvmOpening() {
        withFixture { root ->
            val trace = root.resolve("adb.log")
            val tools = Files.createDirectory(root.resolve("tools"))
            val adb = tools.resolve("adb")
            Files.writeString(
                adb,
                """#!/usr/bin/env bash
set -euo pipefail
serial=${'$'}2
shift 2
printf '%s\n' "${'$'}serial ${'$'}*" >> "${'$'}RKA_SYNTH_TRACE"
case "${'$'}{*: -1}" in
    /proc/sys/kernel/random/boot_id) printf 'synth-%s-boot\n' "${'$'}serial" ;;
    /proc/uptime) printf '123.45 1.0\n' ;;
    *)
        action=
        id=
        nonce=
        while (( ${'$'}# > 0 )); do
            case "${'$'}1" in
                start|sample|finish|verify) action=${'$'}1 ;;
                --id) id=${'$'}2; shift ;;
                --nonce) nonce=${'$'}2; shift ;;
            esac
            shift
        done
        [[ -n "${'$'}action" ]] && printf 'sentinel_id=%s nonce=%s action=%s\n' "${'$'}id" "${'$'}nonce" "${'$'}action"
        ;;
esac
""",
            )
            Files.setPosixFilePermissions(adb, PosixFilePermissions.fromString("rwx------"))

            val result =
                runWrapper(
                    root,
                    hostCommand(root.resolve("baseline.json")),
                    mapOf(
                        "PATH" to "$tools:${System.getenv("PATH")}",
                        "RKA_SYNTH_TRACE" to trace.toString(),
                    ),
                )

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(result.stdout.contains("\"result\":\"SENTINEL_STARTED\""))
            assertFalse(result.stdout.contains(DONOR))
            assertFalse(result.stdout.contains(CANDIDATE))
            assertTrue(Files.exists(root.resolve("baseline.json")))
            assertTrue(Files.readString(trace).contains(DONOR))
            assertTrue(Files.readString(trace).contains(CANDIDATE))
        }
    }

    @Test
    fun sealedChildSnapshotIsCanonicalAndFd3Only() {
        withFixture { root ->
            val hostProbe = root.resolve("rka-host")
            Files.createSymbolicLink(hostProbe, Path.of("/usr/bin/python3"))
            val probe =
                """
import fcntl, hashlib, json, os
value = json.load(open("/proc/self/fd/3", encoding="ascii"))
assert value["donor_serial_sha256"] == hashlib.sha256(value["donor_serial"].encode("ascii")).hexdigest()
assert value["candidate_serial_sha256"] == hashlib.sha256(value["candidate_serial"].encode("ascii")).hexdigest()
assert fcntl.fcntl(3, fcntl.F_GET_SEALS) == 15
assert fcntl.fcntl(3, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
extra = []
for descriptor in range(4, 128):
    try:
        os.fstat(descriptor)
        extra.append(descriptor)
    except OSError:
        pass
print("CANONICAL_FD3=true")
print("EXTRA_FDS=" + ",".join(map(str, extra)))
"""

            val result = runWrapper(root, listOf(hostProbe.toString(), "-c", probe))

            assertEquals(result.stderr, 0, result.exitCode)
            assertEquals("CANONICAL_FD3=true\nEXTRA_FDS=\n", result.stdout)
            assertFalse(result.stdout.contains(DONOR))
            assertFalse(result.stdout.contains(CANDIDATE))
        }
    }

    @Test
    fun malformedDuplicateExtraSameAndOversizedSnapshotsAreRejected() {
        withFixture { root ->
            val pair = root.resolve("device-pair.json")
            val valid = Files.readString(pair).trimEnd()
            val malformed =
                listOf(
                    "" to "PAIR_SNAPSHOT_INVALID",
                    valid.dropLast(1) + ",\"unexpected\":true}\n" to "PAIR_SNAPSHOT_INVALID",
                    valid.replaceFirst(
                        "\"candidate_serial\":",
                        "\"candidate_serial\":\"$CANDIDATE\",\"candidate_serial\":",
                    ) + "\n" to "PAIR_SNAPSHOT_INVALID",
                )
            malformed.forEach { (raw, token) ->
                Files.writeString(pair, raw)
                val result = runWrapper(root, listOf("/bin/true"))
                assertEquals(raw, 2, result.exitCode)
                assertTrue(result.stderr.contains("RESULT=$token"))
            }

            writePair(root, DONOR, DONOR)
            val same = runWrapper(root, listOf("/bin/true"))
            assertEquals(same.stderr, 2, same.exitCode)
            assertTrue(same.stderr.contains("RESULT=PAIR_SNAPSHOT_INVALID"))

            Files.writeString(pair, "x".repeat(65_537))
            val oversized = runWrapper(root, listOf("/bin/true"))
            assertEquals(oversized.stderr, 2, oversized.exitCode)
            assertTrue(oversized.stderr.contains("RESULT=PAIR_SNAPSHOT_OVERSIZED"))
        }
    }

    @Test
    fun lockCoversChildLifetimeAndSignalAndFailureReleaseIt() {
        withFixture { root ->
            val childPid = root.resolve("child.pid")
            val child =
                startWrapper(
                    root,
                    listOf(
                        "sh",
                        "-c",
                        "printf '%s\\n' \"${'$'}${'$'}\" > \"${childPid}\"; exec sleep 30",
                    ),
                )
            repeat(100) {
                if (Files.exists(childPid)) return@repeat
                Thread.sleep(20)
            }
            assertTrue(Files.exists(childPid))

            val contention = runWrapper(root, listOf("/bin/true"))
            assertEquals(contention.stderr, 2, contention.exitCode)
            assertTrue(contention.stderr.contains("RESULT=PAIR_LOCK_BUSY"))

            val pid = Files.readString(childPid).trim().toLong()
            child.destroy()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS))
            assertEquals(143, child.exitValue())
            repeat(100) {
                if (ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
                    Thread.sleep(20)
                }
            }
            assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false))

            val nonzero = runWrapper(root, listOf("sh", "-c", "exit 7"))
            assertEquals(7, nonzero.exitCode)
            val released = runWrapper(root, listOf("/bin/true"))
            assertEquals(released.stderr, 0, released.exitCode)
        }
    }

    private fun hostCommand(baseline: Path): List<String> =
        listOf(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "--enable-native-access=ALL-UNNAMED",
            "-cp",
            System.getProperty("java.class.path"),
            HostCli::class.java.name,
            "sentinel",
            "start",
            "--baseline",
            baseline.toString(),
            "--nonce",
            "SYNTH_NONCE",
        )

    private fun runWrapper(
        root: Path,
        command: List<String>,
        environment: Map<String, String> = emptyMap(),
    ): Result {
        val process = startWrapper(root, command, environment)
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return Result(process.waitFor(), stdout, stderr)
    }

    private fun startWrapper(
        root: Path,
        command: List<String>,
        environment: Map<String, String> = emptyMap(),
    ): Process {
        val repository = Path.of(System.getProperty("user.dir")).parent
        return ProcessBuilder(
                listOf(
                    repository.resolve("scripts/rka-with-device-pair.sh").toString(),
                    "--pair",
                    root.resolve("device-pair.json").toString(),
                    "--",
                ) + command
            )
            .directory(repository.toFile())
            .apply { environment().putAll(environment) }
            .start()
    }

    private fun withFixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("pair-wrapper-")
        try {
            Files.writeString(root.resolve("device-pair.lock"), "")
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            writePair(root, DONOR, CANDIDATE)
            listOf("device-pair.lock").forEach {
                Files.setPosixFilePermissions(
                    root.resolve(it),
                    PosixFilePermissions.fromString("rw-------"),
                )
            }
            block(root)
        } finally {
            Files.walk(root).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private fun writePair(root: Path, donor: String, candidate: String) {
        Files.writeString(
            root.resolve("device-pair.json"),
            """{"candidate_serial":"$candidate","donor_serial":"$donor","profile_sha256":"${"a".repeat(64)}","schema_version":1}
""",
        )
        val encoder = Base64.getUrlEncoder().withoutPadding()
        Files.writeString(
            root.resolve("device-pair.env"),
            "RKA_DEVICE_PAIR_VERSION=1\n" +
                "RKA_DONOR_SERIAL_B64=${encoder.encodeToString(donor.toByteArray())}\n" +
                "RKA_CANDIDATE_SERIAL_B64=${encoder.encodeToString(candidate.toByteArray())}\n" +
                "RKA_PROFILE_SHA256=${"a".repeat(64)}\n",
        )
        listOf("device-pair.json", "device-pair.env").forEach {
            Files.setPosixFilePermissions(
                root.resolve(it),
                PosixFilePermissions.fromString("rw-------"),
            )
        }
    }

    private data class Result(val exitCode: Int, val stdout: String, val stderr: String)

    private companion object {
        const val DONOR = "SYNTH_DONOR"
        const val CANDIDATE = "SYNTH_CANDIDATE"
    }
}
