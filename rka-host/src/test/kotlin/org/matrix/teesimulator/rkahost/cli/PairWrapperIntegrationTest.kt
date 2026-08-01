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
    fun modifiedStandardDeploySourceIsRejectedBeforeExecutionWhenTraceIsActive() {
        withFixture { root ->
            Files.writeString(root.resolve("active-adb-trace-v1"), "active\n")
            Files.setPosixFilePermissions(
                root.resolve("active-adb-trace-v1"),
                PosixFilePermissions.fromString("rw-------"),
            )
            val tools = Files.createDirectory(root.resolve("tools"))
            val fakeHost = tools.resolve("rka-host")
            Files.writeString(fakeHost, "#!/bin/sh\nexit 0\n")
            Files.setPosixFilePermissions(fakeHost, PosixFilePermissions.fromString("rwx------"))
            val mutation = root.resolve("rka-deploy.sh")
            val marker = root.resolve("mutated-deploy-ran")
            Files.writeString(mutation, "#!/bin/sh\nprintf ran > '$marker'\n")
            Files.setPosixFilePermissions(mutation, PosixFilePermissions.fromString("rwx------"))

            val result =
                runWrapper(
                    root,
                    listOf(mutation.toString()),
                    mapOf("PATH" to "$tools:${System.getenv("PATH")}"),
                )

            assertEquals(2, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=DEPLOY_SOURCE_MISMATCH"))
            assertFalse(Files.exists(marker))
        }
    }

    @Test
    fun absoluteAlternateBasenameMasqueradeAndAdapterUnsetChildrenAreRejected() {
        withFixture { root ->
            Files.writeString(root.resolve("active-adb-trace-v1"), "active\n")
            Files.setPosixFilePermissions(
                root.resolve("active-adb-trace-v1"),
                PosixFilePermissions.fromString("rw-------"),
            )
            val tools = Files.createDirectory(root.resolve("tools"))
            val fakeHost = tools.resolve("rka-host")
            Files.writeString(fakeHost, "#!/bin/sh\nexit 0\n")
            Files.setPosixFilePermissions(fakeHost, PosixFilePermissions.fromString("rwx------"))
            val alternate = root.resolve("alternate.sh")
            val masquerade = root.resolve("rka-deploy.sh")
            listOf(alternate, masquerade).forEach {
                Files.writeString(it, "#!/bin/sh\nexit 0\n")
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
            }
            val environment = mapOf("PATH" to "$tools:${System.getenv("PATH")}")

            val absolute = runWrapper(root, listOf("/bin/true"), environment)
            val alternateResult = runWrapper(root, listOf(alternate.toString()), environment)
            val masqueradeResult = runWrapper(root, listOf(masquerade.toString()), environment)
            val adapterUnset =
                runWrapper(
                    root,
                    listOf(
                        "/usr/bin/env",
                        "-u",
                        "RKA_DEPLOY_ADB",
                        Path.of(System.getProperty("user.dir"))
                            .parent
                            .resolve("scripts/rka-deploy.sh")
                            .toString(),
                    ),
                    environment,
                )

            assertTrue(absolute.stderr.contains("RESULT=TRACE_CHILD_UNAUTHORIZED"))
            assertTrue(alternateResult.stderr.contains("RESULT=TRACE_CHILD_UNAUTHORIZED"))
            assertTrue(masqueradeResult.stderr.contains("RESULT=DEPLOY_SOURCE_MISMATCH"))
            assertTrue(adapterUnset.stderr.contains("RESULT=TRACE_CHILD_UNAUTHORIZED"))
        }
    }

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
if [[ " ${'$'}* " == *' shell su 0 sh '* ]]; then
    IFS= read -r private_header
    [[ "${'$'}private_header" == "exec 3<<'RKA_PRIVATE_INPUT_V1'" ]]
    while IFS= read -r private_line; do
        [[ "${'$'}private_line" != RKA_PRIVATE_INPUT_V1 ]] || break
    done
    IFS= read -r fixed
    [[ "${'$'}fixed" == 'set -- '* ]]
    fixed=${'$'}{fixed#'set -- '}
    read -r action id _ <<< "${'$'}fixed"
    phase=ROOT_AUTHORITATIVE
    samples=2
    [[ "${'$'}action" != start ]] || samples=1
    [[ "${'$'}action" != stop ]] || phase=STOPPED
    printf 'sentinel_id=%s action=%s phase=%s samples=%s\n' "${'$'}id" "${'$'}action" "${'$'}phase" "${'$'}samples"
    exit 0
fi
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
            val traceText = Files.readString(trace)
            assertTrue(traceText.contains(DONOR))
            assertTrue(traceText.contains(CANDIDATE))
            assertTrue(traceText.contains("shell su 0 sh"))
            assertFalse(traceText.contains(RKA_CONTROL_PATH))
            val baseline = Files.readString(root.resolve("baseline.json"))
            assertFalse(baseline.contains(DONOR))
            assertFalse(baseline.contains(CANDIDATE))

            writePair(root, "REBOUND_DONOR", "REBOUND_CANDIDATE")
            Files.writeString(trace, "")
            val crossPair =
                runWrapper(
                    root,
                    hostAction(root.resolve("baseline.json"), "assert-live"),
                    mapOf(
                        "PATH" to "$tools:${System.getenv("PATH")}",
                        "RKA_SYNTH_TRACE" to trace.toString(),
                    ),
                )
            assertEquals(2, crossPair.exitCode)
            assertTrue(crossPair.stderr.contains("PAIR_BINDING_MISMATCH"))
            assertTrue(Files.readString(trace).isEmpty())
            writePair(root, DONOR, CANDIDATE)

            Files.writeString(trace, "")
            val donorOnly =
                runWrapper(
                    root,
                    hostCommand(root.resolve("donor-baseline.json"), "donor"),
                    mapOf(
                        "PATH" to "$tools:${System.getenv("PATH")}",
                        "RKA_SYNTH_TRACE" to trace.toString(),
                    ),
                )
            assertEquals(donorOnly.stderr, 0, donorOnly.exitCode)
            assertTrue(Files.readString(trace).contains(DONOR))
            assertFalse(Files.readString(trace).contains(CANDIDATE))

            Files.writeString(trace, "")
            val wrongScope =
                runWrapper(
                    root,
                    hostCommand(root.resolve("wrong-baseline.json"), "candidate"),
                    mapOf(
                        "PATH" to "$tools:${System.getenv("PATH")}",
                        "RKA_SYNTH_TRACE" to trace.toString(),
                    ),
                )
            assertEquals(2, wrongScope.exitCode)
            assertTrue(Files.readString(trace).isEmpty())
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
    fun childEnvironmentContainsOnlyFd3PairTransport() {
        withFixture { root ->
            val probe =
                """
import os
for name in (
    "RKA_DEVICE_PAIR_VERSION",
    "RKA_DONOR_SERIAL_B64",
    "RKA_CANDIDATE_SERIAL_B64",
    "RKA_PROFILE_SHA256",
):
    print(name + "_PRESENT=" + str(name in os.environ).lower())
print("PAIR_FD_EXACT=" + str(os.environ.get("RKA_DEVICE_PAIR_FD") == "3").lower())
print("ORDINARY_ENV_PRESERVED=" + str(os.environ.get("RKA_SYNTH_KEEP") == "present").lower())
"""
            val inherited =
                mapOf(
                    "RKA_DEVICE_PAIR_VERSION" to "synthetic",
                    "RKA_DONOR_SERIAL_B64" to "synthetic",
                    "RKA_CANDIDATE_SERIAL_B64" to "synthetic",
                    "RKA_PROFILE_SHA256" to "synthetic",
                    "RKA_DEVICE_PAIR_FD" to "99",
                    "RKA_SYNTH_KEEP" to "present",
                )

            val result = runWrapper(root, listOf("python3", "-c", probe), inherited)

            assertEquals(result.stderr, 0, result.exitCode)
            val expected =
                SENSITIVE_ENVIRONMENT_NAMES.joinToString("\n", postfix = "\n") {
                    "${it}_PRESENT=false"
                } + "PAIR_FD_EXACT=true\nORDINARY_ENV_PRESERVED=true\n"
            assertEquals(result.stdout, expected, result.stdout)
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

    private fun hostCommand(baseline: Path, scope: String? = null): List<String> =
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
        ) + if (scope == null) emptyList() else listOf("--scope", scope)

    private fun hostAction(baseline: Path, action: String): List<String> =
        listOf(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "--enable-native-access=ALL-UNNAMED",
            "-cp",
            System.getProperty("java.class.path"),
            HostCli::class.java.name,
            "sentinel",
            action,
            "--baseline",
            baseline.toString(),
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
        val SENSITIVE_ENVIRONMENT_NAMES =
            listOf(
                "RKA_DEVICE_PAIR_VERSION",
                "RKA_DONOR_SERIAL_B64",
                "RKA_CANDIDATE_SERIAL_B64",
                "RKA_PROFILE_SHA256",
            )
    }
}
