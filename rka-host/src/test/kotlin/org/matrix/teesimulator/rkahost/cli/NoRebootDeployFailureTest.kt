package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NoRebootDeployFailureTest {
    @Test
    fun exactCompatibilityMismatchStopsBeforeAnyMutation() {
        Fixture(incompatible = "CANDIDATE_B").use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=KSU_COMPATIBILITY_MISMATCH"))
            assertTrue(fixture.trace().all { "preflight" in it })
            assertFalse(fixture.trace().any { "push" in it || "deploy" in it || "rollback" in it })
        }
    }

    @Test
    fun sameArchiveDeploysDistinctRolesAndPublicPinsWithoutReboot() {
        Fixture().use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(result.stdout.contains("\"result\":\"DEPLOYED_NO_REBOOT\""))
            val trace = fixture.trace()
            val pushes = trace.filter { " push " in " $it " }
            assertEquals(2, pushes.size)
            assertEquals(
                pushes[0].substringAfter("push ").substringBeforeLast(' '),
                pushes[1].substringAfter("push ").substringBeforeLast(' '),
            )
            assertTrue(trace.any { Regex("deploy .* DONOR$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("deploy .* CANDIDATE$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("pair .* DONOR ").containsMatchIn(it) })
            assertTrue(trace.any { Regex("pair .* CANDIDATE ").containsMatchIn(it) })
            assertTrue(trace.any { "direct-probe" in it })
            assertFalse(trace.any { forbidden.containsMatchIn(it) })
        }
    }

    @Test
    fun failedSecondInstallRollsBackBothSidesWithoutFallback() {
        Fixture(failDeploy = "CANDIDATE_B").use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            val trace = fixture.trace()
            assertTrue(trace.any { Regex("rollback .* CANDIDATE$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("rollback .* DONOR$").containsMatchIn(it) })
            assertFalse(trace.any { "usb" in it.lowercase() || forbidden.containsMatchIn(it) })
        }
    }

    @Test
    fun failedFirstInstallStillRunsIdempotentPairRollback() {
        Fixture(failDeploy = "DONOR_A").use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            val trace = fixture.trace()
            assertTrue(trace.any { Regex("rollback .* CANDIDATE$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("rollback .* DONOR$").containsMatchIn(it) })
            assertFalse(trace.any { "usb" in it.lowercase() || forbidden.containsMatchIn(it) })
        }
    }

    @Test
    fun directOnlyCliRejectsUsbBeforeDeviceAccess() {
        Fixture().use { fixture ->
            val result = fixture.run(network = "usb")

            assertEquals(2, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=ARGUMENT_INVALID"))
            assertTrue(fixture.trace().isEmpty())
        }
    }

    @Test
    fun unavailableDirectPathStopsBeforeArchivePush() {
        Fixture(failNetwork = "CANDIDATE_B").use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=DIRECT_PATH_UNAVAILABLE"))
            assertFalse(fixture.trace().any { "push" in it || "deploy" in it })
        }
    }

    private class Fixture(
        private val incompatible: String? = null,
        private val failDeploy: String? = null,
        private val failNetwork: String? = null,
    ) : java.io.Closeable {
        private val root = Files.createTempDirectory("no-reboot-deploy-")
        private val log = root.resolve("adb.log")
        private val pair = root.resolve("device-pair.json")
        private val zip = root.resolve("release.zip")
        private val evidence = root.resolve("evidence.json")
        private val adb = root.resolve("adb")

        init {
            Files.writeString(
                pair,
                """{"candidate_serial":"CANDIDATE_B","donor_serial":"DONOR_A","profile_sha256":"${"a".repeat(64)}","schema_version":1}""" +
                    "\n",
            )
            val archiveRoot = root.resolve("archive")
            val entries =
                listOf(
                    "META-INF/rka-artifacts.sha256",
                    "module.prop",
                    "rka-control.sh",
                    "rka-runtime.manifest",
                    "rka-sidecar",
                    "rka-supervisor.sh",
                    "sepolicy.probes",
                    "sepolicy.rule",
                    "webroot/index.html",
                )
            entries.forEach { entry ->
                archiveRoot.resolve(entry).also {
                    Files.createDirectories(it.parent)
                    Files.writeString(it, "fixture-$entry\n")
                }
            }
            val zipped =
                ProcessBuilder("zip", "-qr", zip.toString(), ".")
                    .directory(archiveRoot.toFile())
                    .start()
            check(zipped.waitFor() == 0)
            val sourceSha =
                ProcessBuilder("git", "rev-parse", "HEAD")
                    .directory(Path.of(System.getProperty("user.dir")).parent.toFile())
                    .start()
                    .let { process ->
                        val value = process.inputStream.bufferedReader().readText().trim()
                        check(process.waitFor() == 0)
                        value
                    }
            Files.writeString(Path.of("${zip}.source-sha"), "$sourceSha\n")
            Files.writeString(adb, fakeAdb)
            Files.setPosixFilePermissions(adb, PosixFilePermissions.fromString("rwx------"))
        }

        fun run(network: String = "direct-auto"): Result {
            val projectRoot = Path.of(System.getProperty("user.dir")).parent
            val script = projectRoot.resolve("scripts/rka-deploy.sh")
            val command =
                "exec 3<\"$pair\"; exec \"$script\" --pair-fd-env RKA_DEVICE_PAIR_FD --zip \"$zip\" --network \"$network\" --no-reboot --evidence \"$evidence\""
            val process =
                ProcessBuilder("bash", "-c", command)
                    .directory(projectRoot.toFile())
                    .apply {
                        environment()["RKA_DEVICE_PAIR_FD"] = "3"
                        environment()["RKA_DEPLOY_ADB"] = adb.toString()
                        environment()["RKA_FAKE_LOG"] = log.toString()
                        incompatible?.let { environment()["RKA_FAKE_INCOMPATIBLE"] = it }
                        failDeploy?.let { environment()["RKA_FAKE_FAIL_DEPLOY"] = it }
                        failNetwork?.let { environment()["RKA_FAKE_FAIL_NETWORK"] = it }
                    }
                    .start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            return Result(process.waitFor(), stdout, stderr)
        }

        fun trace(): List<String> = if (Files.exists(log)) Files.readAllLines(log) else emptyList()

        override fun close() {
            root.toFile().deleteRecursively()
        }
    }

    private data class Result(val exitCode: Int, val stdout: String, val stderr: String)

    private companion object {
        val forbidden = Regex("(^| )(reboot|soft-reboot|late-load|services|usb)( |$)")
        val fakeAdb =
            """#!/bin/bash
set -eu
serial=${'$'}2
shift 2
printf '%s %s\n' "${'$'}serial" "${'$'}*" >> "${'$'}RKA_FAKE_LOG"
case " ${'$'}* " in
  *" preflight "*)
    if [ "${'$'}{RKA_FAKE_INCOMPATIBLE:-}" = "${'$'}serial" ]; then
      printf '%s\n' 'RESULT=INCOMPATIBLE reason=KSUD_VERSION'
    else
      printf '%s\n' 'RESULT=COMPATIBLE boot_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa active_hash=ABSENT pending_hash=ABSENT bind_hash=ABSENT'
    fi
    ;;
  *" network "*)
    if [ "${'$'}{RKA_FAKE_FAIL_NETWORK:-}" = "${'$'}serial" ]; then exit 1; fi
    if [ "${'$'}serial" = DONOR_A ]; then endpoint=100.64.0.1; else endpoint=100.64.0.2; fi
    printf 'RESULT=NETWORK endpoint=%s\n' "${'$'}endpoint"
    ;;
  *" mkdir -p "*) exit 0 ;;
  *" push "*) exit 0 ;;
  *" deploy "*)
    role=${'$'}{*: -1}
    if [ "${'$'}{RKA_FAKE_FAIL_DEPLOY:-}" = "${'$'}serial" ]; then exit 1; fi
    if [ "${'$'}role" = DONOR ]; then pin=1111111111111111111111111111111111111111111111111111111111111111; else pin=2222222222222222222222222222222222222222222222222222222222222222; fi
    printf 'RESULT=DEPLOYED role=%s staged_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb pin=%s\n' "${'$'}role" "${'$'}pin"
    ;;
  *" pair "*) printf '%s\n' 'RESULT=PAIRED' ;;
  *" direct-probe "*) printf '%s\n' 'RESULT=DIRECT' ;;
  *" verify "*) printf '%s\n' 'RESULT=VERIFIED boot_unchanged=true' ;;
  *" rollback "*) printf '%s\n' 'RESULT=ROLLED_BACK' ;;
  *) exit 1 ;;
esac
"""
    }
}
