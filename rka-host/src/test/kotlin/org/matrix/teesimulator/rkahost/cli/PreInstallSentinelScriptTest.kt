package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PreInstallSentinelScriptTest {
    @Test
    fun samplesBeforeInstallAndKeepsAuthorityThroughInstalledRuntimeTransition() =
        withFixture { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)
            val preInstall = fixture.action("assert-live")
            assertEquals(preInstall.stderr, 0, preInstall.exitCode)
            assertTrue(preInstall.stdout.contains("phase=ROOT_AUTHORITATIVE"))

            fixture.installRuntime()
            Thread.sleep(2_300)
            val installed = fixture.action("assert-live")
            assertEquals(installed.stderr, 0, installed.exitCode)
            assertTrue(installed.stdout.contains("phase=INSTALLED_OBSERVED"))
            assertTrue(fixture.maximumGapMillis() <= 2_000)

            assertEquals(0, fixture.action("stop").exitCode)
            assertEquals(0, fixture.action("stop").exitCode)
            assertFalse(Files.exists(fixture.sentinel))
        }

    @Test
    fun rejectsBootPropertyServiceTraceAndMalformedSampleDrift() {
        val mutations =
            listOf<(Fixture) -> Unit>(
                { it.replaceInFirstSample("boot_sha256=", "boot_sha256=${"d".repeat(64)}") },
                {
                    it.replaceInFirstSample("property_sha256=", "property_sha256=${"e".repeat(64)}")
                },
                { it.replaceInFirstSample("keystore2=", "keystore2=7:9:${"f".repeat(64)}") },
                { it.replaceInFirstSample("trace=", "trace=FORBIDDEN") },
                { it.replaceInFirstSample("forbidden_pids=", "forbidden_pids=7") },
                { it.appendToFirstSample("unexpected=true\n") },
            )
        mutations.forEach { mutation ->
            withFixture { fixture ->
                assertEquals(0, fixture.action("start").exitCode)
                Thread.sleep(2_300)
                mutation(fixture)
                assertTrue(fixture.action("assert-live").exitCode != 0)
            }
        }
    }

    @Test
    fun rejectsNonIncreasingGapAndDeadOrStaleSampler() {
        withFixture { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)
            fixture.replaceLastUptimeWithPrevious()
            assertTrue(fixture.action("assert-live").exitCode != 0)
        }
        withFixture { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)
            fixture.replaceLastUptimeWithPrevious(2_001)
            assertTrue(fixture.action("assert-live").exitCode != 0)
        }
        withFixture { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)
            fixture.killSampler()
            assertTrue(fixture.action("assert-live").exitCode != 0)
        }
        withFixture { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)
            Files.writeString(fixture.sentinel.resolve("pid_start"), "1\n")
            assertTrue(fixture.action("assert-live").exitCode != 0)
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val fixture = Fixture()
        try {
            block(fixture)
        } finally {
            fixture.close()
        }
    }

    private class Fixture {
        private val root = Files.createTempDirectory("preinstall-sentinel-")
        private val tools = Files.createDirectory(root.resolve("tools"))
        private val runtime = Files.createDirectory(root.resolve("runtime"))
        private val module = Files.createDirectory(root.resolve("module"))
        private val state = Files.createDirectory(root.resolve("state"))
        private val script =
            Path.of(System.getProperty("user.dir"))
                .resolve("src/main/resources/rka-preinstall-sentinel.sh")
        val sentinel: Path = runtime.resolve(ID)

        init {
            listOf(root, tools, runtime, module, state).forEach {
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
            }
            executable("pidof", "#!/bin/sh\nexit 1\n")
            executable("getprop", "#!/bin/sh\nprintf 'stable-value\\n'\n")
            executable("logcat", "#!/bin/sh\nexit 0\n")
        }

        fun action(action: String): Result {
            val process =
                ProcessBuilder(
                        "sh",
                        script.toString(),
                        action,
                        ID,
                        NONCE_HASH,
                        "DONOR",
                        SCRIPT_HASH,
                    )
                    .apply {
                        environment()["PATH"] = "$tools:${environment()["PATH"]}"
                        environment()["RKA_SENTINEL_ROOT"] = runtime.toString()
                        environment()["RKA_SENTINEL_CONTROL"] =
                            module.resolve("rka-control.sh").toString()
                        environment()["RKA_SENTINEL_STATE_ROOT"] = state.toString()
                    }
                    .start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            return Result(process.waitFor(), stdout, stderr)
        }

        fun installRuntime() {
            val control = module.resolve("rka-control.sh")
            Files.writeString(control, "#!/bin/sh\nexit 0\n")
            Files.setPosixFilePermissions(control, PosixFilePermissions.fromString("rwx------"))
            val metadata = Files.createDirectories(module.resolve("META-INF"))
            Files.writeString(
                metadata.resolve("rka-artifacts.sha256"),
                "${Hashes.sha256(Files.readAllBytes(control))}  rka-control.sh\n",
            )
            val run = Files.createDirectories(state.resolve("run"))
            val boot = Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim()
            Files.writeString(
                run.resolve("boot-continuity.state"),
                "version=1\nsentinel_id=${"1".repeat(32)}\nboot_id=$boot\nsample_ms=1\n",
            )
        }

        fun maximumGapMillis(): Long {
            val count = Files.readString(sentinel.resolve("count")).trim().toInt()
            return (1..count)
                .map { sequence ->
                    Files.readAllLines(sentinel.resolve("samples/$sequence"))[5].substringAfter('=')
                        .toLong()
                }
                .zipWithNext { before, after -> after - before }
                .max()
        }

        fun replaceInFirstSample(prefix: String, replacement: String) {
            val sample = sentinel.resolve("samples/1")
            Files.writeString(
                sample,
                Files.readAllLines(sample).joinToString("\n", postfix = "\n") {
                    if (it.startsWith(prefix)) replacement else it
                },
            )
        }

        fun appendToFirstSample(value: String) {
            val sample = sentinel.resolve("samples/1")
            Files.writeString(sample, Files.readString(sample) + value)
        }

        fun replaceLastUptimeWithPrevious(delta: Long = 0) {
            val count = Files.readString(sentinel.resolve("count")).trim().toInt()
            val previous =
                Files.readAllLines(sentinel.resolve("samples/${count - 1}"))[5].substringAfter('=')
                    .toLong()
            val sample = sentinel.resolve("samples/$count")
            Files.writeString(
                sample,
                Files.readAllLines(sample).joinToString("\n", postfix = "\n") {
                    if (it.startsWith("uptime_ms=")) "uptime_ms=${previous + delta}" else it
                },
            )
        }

        fun killSampler() {
            ProcessHandle.of(Files.readString(sentinel.resolve("pid")).trim().toLong()).ifPresent {
                it.destroyForcibly()
                repeat(50) { _ -> if (it.isAlive) Thread.sleep(10) }
            }
        }

        fun close() {
            if (Files.exists(sentinel)) {
                action("stop")
                if (Files.exists(sentinel)) {
                    killSampler()
                    Files.walk(sentinel)
                        .sorted(Comparator.reverseOrder())
                        .forEach(Files::deleteIfExists)
                }
            }
            Files.walk(root).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }

        private fun executable(name: String, body: String) {
            val path = tools.resolve(name)
            Files.writeString(path, body)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        }
    }

    private data class Result(val exitCode: Int, val stdout: String, val stderr: String)

    private companion object {
        const val ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val NONCE_HASH = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val SCRIPT_HASH = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
}
