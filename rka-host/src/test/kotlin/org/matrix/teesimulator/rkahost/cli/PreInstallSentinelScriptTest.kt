package org.matrix.teesimulator.rkahost.cli

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PreInstallSentinelScriptTest {
    @Test
    fun samplerClosesInheritedAndroidControlDescriptorsAfterFork() = withFixture { fixture ->
        val started = fixture.actionThroughAndroidControlDescriptors()

        assertTrue(fixture.sampleCount() >= 1)
        assertTrue(Files.exists(fixture.sentinel.resolve("samples/1")))
        assertTrue(Files.exists(fixture.sentinel.resolve("pid")))
        assertEquals(started.stderr, 0, started.exitCode)
        assertTrue(started.stdout.contains("action=start"))
        assertEquals(listOf("0", "1", "2"), fixture.samplerDescriptors())
        assertFalse(started.stdout.contains("synthetic.alpha"))
        assertFalse(started.stderr.contains("synthetic.alpha"))
    }

    @Test
    fun hostileBlockingLogcatIsNeverInvokedByAuthoritativeIdentitySampler() =
        withFixture { fixture ->
            val started = fixture.action("start", 2_000)

            assertEquals(started.stderr, 0, started.exitCode)
            assertEquals(0, fixture.logcatInvocations())
        }

    @Test
    fun shippedSamplerIsPolicyAgnosticAndReadsPrivateSyntheticKeys() = withFixture { fixture ->
        val source = Files.readString(fixture.script)
        assertFalse(source.contains("ro.build."))
        assertFalse(source.contains("ro.vendor."))
        assertFalse(source.contains("logcat"))

        val started = fixture.action("start")
        assertEquals(started.stderr, 0, started.exitCode)
        Thread.sleep(1_300)
        assertEquals(listOf("synthetic.alpha", "synthetic.beta"), fixture.requestedProperties())
    }

    @Test
    fun exactLastAllowedFrameSucceedsAndNextTickFailsClosedWithoutOverwrite() {
        withFixture(maxSamples = 2) { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)

            assertEquals(2, fixture.sampleCount())
            assertTrue(Files.exists(fixture.sentinel.resolve("samples/2")))
            assertFalse(Files.exists(fixture.sentinel.resolve("samples/3")))
            val exhausted = fixture.action("assert-live")
            assertTrue(exhausted.exitCode != 0)
            assertTrue(exhausted.stdout.contains("result=SENTINEL_SAMPLE_LIMIT"))
        }
    }

    @Test
    fun durationLimitFailsClosedWithCompletePriorFrames() {
        withFixture(maxSamples = 8, maxDurationSeconds = 1) { fixture ->
            assertEquals(0, fixture.action("start").exitCode)
            Thread.sleep(2_300)

            val exhausted = fixture.action("assert-live")
            assertTrue(exhausted.exitCode != 0)
            assertTrue(exhausted.stdout.contains("result=SENTINEL_DURATION_LIMIT"))
            assertTrue(fixture.sampleCount() in 1..8)
            assertTrue(Files.exists(fixture.sentinel.resolve("samples/1")))
        }
    }

    @Test
    fun everyAtomicFrameBindsNonceRoleSequenceAndCompletion() = withFixture { fixture ->
        assertEquals(0, fixture.action("start").exitCode)
        Thread.sleep(1_300)

        val lines = Files.readAllLines(fixture.sentinel.resolve("samples/1"))
        assertTrue(lines.contains("nonce_sha256=$NONCE_HASH"))
        assertTrue(lines.contains("role=DONOR"))
        assertTrue(lines.contains("sequence=1"))
        assertEquals("complete=1", lines.last())
    }

    @Test
    fun rejectsCrossNonceFrameAtAuthoritativeBoundary() = withFixture { fixture ->
        assertEquals(0, fixture.action("start").exitCode)
        Thread.sleep(1_300)
        fixture.replaceInFirstSample("nonce_sha256=", "nonce_sha256=${"d".repeat(64)}")
        assertTrue(fixture.action("assert-live").exitCode != 0)
    }

    @Test
    fun rejectsPartialPublicationAndFileCountMismatch() = withFixture { fixture ->
        assertEquals(0, fixture.action("start").exitCode)
        Thread.sleep(1_300)
        fixture.addPartialFrame()
        assertTrue(fixture.action("assert-live").exitCode != 0)
    }

    @Test
    fun task25RejectsServiceRestartDriftAndStillCleansBoundedTree() = withFixture { fixture ->
        assertEquals(0, fixture.action("start").exitCode)
        Thread.sleep(1_300)
        fixture.replaceInFirstSample("keystore2=", "keystore2=7:9:${"f".repeat(64)}")
        assertTrue(fixture.action("assert-live").exitCode != 0)
        assertEquals(0, fixture.action("stop").exitCode)
        assertFalse(Files.exists(fixture.sentinel))
    }

    @Test
    fun rejectsMalformedOversizedDuplicateReplayOrderAndBindingFrames() {
        val mutations =
            listOf<(Fixture) -> Unit>(
                { it.appendToFirstSample("duplicate=1\n") },
                { it.appendToFirstSample("oversized=${"x".repeat(1_024)}\n") },
                { it.replaceInFirstSample("version=", "version=2") },
                { it.replaceInFirstSample("nonce_sha256=", "nonce_sha256=${"d".repeat(64)}") },
                { it.replaceInFirstSample("sentinel_id=", "sentinel_id=${"e".repeat(64)}") },
                { it.replaceInFirstSample("role=", "role=CANDIDATE") },
                { it.replayFirstFrameAsSecond() },
                { it.swapFirstTwoFrames() },
                { it.removeCompletionMarker() },
                { it.addPartialFrame() },
                { it.replaceFirstFrameWithSymlink() },
                { it.writeCount("1") },
                { it.writeCount("999") },
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
    fun rejectsAsymmetricSymlinkAndFileRuntimeLayoutsBeforeSampling() {
        listOf<(Fixture) -> Unit>(
                { it.installControlWithoutManifest() },
                { it.replaceModuleWithSymlink() },
                { it.replaceModuleWithFile() },
                { it.installSymlinkControl() },
            )
            .forEach { mutation ->
                withFixture { fixture ->
                    mutation(fixture)
                    assertTrue(fixture.action("start").exitCode != 0)
                    assertFalse(Files.exists(fixture.sentinel))
                }
            }
    }

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
    fun rejectsBootPropertyServiceForbiddenAndMalformedSampleDrift() {
        val mutations =
            listOf<(Fixture) -> Unit>(
                { it.replaceInFirstSample("boot_sha256=", "boot_sha256=${"d".repeat(64)}") },
                {
                    it.replaceInFirstSample("property_sha256=", "property_sha256=${"e".repeat(64)}")
                },
                { it.replaceInFirstSample("keystore2=", "keystore2=7:9:${"f".repeat(64)}") },
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

    private fun withFixture(
        maxSamples: Int = 8,
        maxDurationSeconds: Int = maxSamples * 2,
        block: (Fixture) -> Unit,
    ) {
        val fixture = Fixture(maxSamples, maxDurationSeconds)
        try {
            block(fixture)
        } finally {
            fixture.close()
        }
    }

    private class Fixture(private val maxSamples: Int, private val maxDurationSeconds: Int) {
        private val root = Files.createTempDirectory("preinstall-sentinel-")
        private val tools = Files.createDirectory(root.resolve("tools"))
        private val runtime = Files.createDirectory(root.resolve("runtime"))
        private val module = Files.createDirectory(root.resolve("module"))
        private val state = Files.createDirectory(root.resolve("state"))
        val script =
            Path.of(System.getProperty("user.dir"))
                .resolve("src/main/resources/rka-preinstall-sentinel.sh")
        private val privateProperties = root.resolve("property-allowlist")
        private val propertyTrace = root.resolve("property-trace")
        val sentinel: Path = runtime.resolve(ID)

        init {
            listOf(root, tools, runtime, module, state).forEach {
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
            }
            executable("pidof", "#!/bin/sh\nexit 1\n")
            executable(
                "getprop",
                "#!/bin/sh\nprintf '%s\\n' \"${'$'}1\" >> \"${propertyTrace}\"\nprintf 'stable-value\\n'\n",
            )
            executable(
                "logcat",
                "#!/bin/sh\nprintf 'invoked\\n' >> '${root.resolve("logcat-invocations")}'\nwhile sleep 1; do :; done\n",
            )
            Files.writeString(privateProperties, "synthetic.alpha\nsynthetic.beta\n")
            Files.setPosixFilePermissions(
                privateProperties,
                PosixFilePermissions.fromString("rw-------"),
            )
        }

        fun action(action: String, timeoutMillis: Long = 5_000): Result {
            val process =
                ProcessBuilder(
                        "sh",
                        "-c",
                        "exec 3<\"${'$'}1\"; shift; exec \"${'$'}@\"",
                        "sentinel-test",
                        privateProperties.toString(),
                        "sh",
                        script.toString(),
                        action,
                        ID,
                        NONCE_HASH,
                        "DONOR",
                        SCRIPT_HASH,
                        maxSamples.toString(),
                        maxDurationSeconds.toString(),
                        "1024",
                        (maxSamples * 1024 + 8192).toString(),
                        (maxSamples + 6).toString(),
                        "256",
                    )
                    .apply {
                        environment()["PATH"] = "$tools:${environment()["PATH"]}"
                        environment()["RKA_SENTINEL_ROOT"] = runtime.toString()
                        environment()["RKA_SENTINEL_CONTROL"] =
                            module.resolve("rka-control.sh").toString()
                        environment()["RKA_SENTINEL_STATE_ROOT"] = state.toString()
                    }
                    .start()
            if (!process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                process.waitFor()
                return Result(124, "", "SAMPLER_TIMEOUT")
            }
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            return Result(process.exitValue(), stdout, stderr)
        }

        fun actionThroughAndroidControlDescriptors(): Result {
            val androidSu = root.resolve("android-su")
            Files.writeString(
                androidSu,
                """
                #!/bin/sh
                set -eu
                exec 3<"${'$'}1"
                shift
                exec 47>&1
                exec 63>&2
                exec "${'$'}@"
                """
                    .trimIndent()
                    .plus("\n"),
            )
            Files.setPosixFilePermissions(androidSu, PosixFilePermissions.fromString("rwx------"))
            val process =
                ProcessBuilder(
                        androidSu.toString(),
                        privateProperties.toString(),
                        "sh",
                        script.toString(),
                        "start",
                        ID,
                        NONCE_HASH,
                        "DONOR",
                        SCRIPT_HASH,
                        maxSamples.toString(),
                        maxDurationSeconds.toString(),
                        "1024",
                        (maxSamples * 1024 + 8192).toString(),
                        (maxSamples + 6).toString(),
                        "256",
                    )
                    .apply {
                        environment()["PATH"] = "$tools:${environment()["PATH"]}"
                        environment()["RKA_SENTINEL_ROOT"] = runtime.toString()
                        environment()["RKA_SENTINEL_CONTROL"] =
                            module.resolve("rka-control.sh").toString()
                        environment()["RKA_SENTINEL_STATE_ROOT"] = state.toString()
                    }
                    .start()
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            val stdoutReader = Thread { process.inputStream.use { it.copyTo(stdout) } }
            val stderrReader = Thread { process.errorStream.use { it.copyTo(stderr) } }
            stdoutReader.start()
            stderrReader.start()
            val processExited = process.waitFor(2, TimeUnit.SECONDS)
            stdoutReader.join(2_000)
            stderrReader.join(2_000)
            if (stdoutReader.isAlive || stderrReader.isAlive) {
                val descriptors = samplerDescriptors()
                val stdoutWasAlive = stdoutReader.isAlive
                val stderrWasAlive = stderrReader.isAlive
                killSampler()
                stdoutReader.join(2_000)
                stderrReader.join(2_000)
                return Result(
                    124,
                    stdout.toString(Charsets.UTF_8),
                    "SAMPLER_TIMEOUT processExited=$processExited stdoutAlive=$stdoutWasAlive stderrAlive=$stderrWasAlive descriptors=$descriptors sourceHasSweep=${Files.readString(script).contains("for inherited_fd_path")}",
                )
            }
            return Result(
                process.exitValue(),
                stdout.toString(Charsets.UTF_8),
                stderr.toString(Charsets.UTF_8),
            )
        }

        fun logcatInvocations(): Int {
            val path = root.resolve("logcat-invocations")
            return if (Files.exists(path)) Files.readAllLines(path).size else 0
        }

        fun sampleCount(): Int = Files.readString(sentinel.resolve("count")).trim().toInt()

        fun samplerDescriptors(): List<String> {
            val pid = Files.readString(sentinel.resolve("pid")).trim()
            return Files.list(Path.of("/proc/$pid/fd")).use { paths ->
                paths.map { it.fileName.toString() }.sorted().toList()
            }
        }

        fun requestedProperties(): List<String> =
            if (Files.exists(propertyTrace)) Files.readAllLines(propertyTrace).distinct()
            else emptyList()

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
                    Files.readAllLines(sentinel.resolve("samples/$sequence"))
                        .single { it.startsWith("uptime_ms=") }
                        .substringAfter('=')
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

        fun replayFirstFrameAsSecond() {
            Files.write(
                sentinel.resolve("samples/2"),
                Files.readAllBytes(sentinel.resolve("samples/1")),
            )
        }

        fun swapFirstTwoFrames() {
            val first = Files.readAllBytes(sentinel.resolve("samples/1"))
            val second = Files.readAllBytes(sentinel.resolve("samples/2"))
            Files.write(sentinel.resolve("samples/1"), second)
            Files.write(sentinel.resolve("samples/2"), first)
        }

        fun removeCompletionMarker() {
            val sample = sentinel.resolve("samples/1")
            Files.writeString(
                sample,
                Files.readAllLines(sample).dropLast(1).joinToString("\n", postfix = "\n"),
            )
        }

        fun addPartialFrame() {
            Files.writeString(sentinel.resolve("samples/.sample-partial.tmp"), "version=3\n")
        }

        fun replaceFirstFrameWithSymlink() {
            val first = sentinel.resolve("samples/1")
            Files.delete(first)
            Files.createSymbolicLink(first, sentinel.resolve("samples/2"))
        }

        fun writeCount(value: String) {
            Files.writeString(sentinel.resolve("count"), "$value\n")
        }

        fun installControlWithoutManifest() {
            Files.writeString(module.resolve("rka-control.sh"), "#!/bin/sh\nexit 0\n")
        }

        fun replaceModuleWithSymlink() {
            Files.delete(module)
            val target = Files.createDirectory(root.resolve("module-target"))
            Files.createSymbolicLink(module, target)
        }

        fun replaceModuleWithFile() {
            Files.delete(module)
            Files.writeString(module, "not-a-directory\n")
        }

        fun installSymlinkControl() {
            val target = root.resolve("control-target")
            Files.writeString(target, "#!/bin/sh\nexit 0\n")
            Files.createSymbolicLink(module.resolve("rka-control.sh"), target)
            val metadata = Files.createDirectories(module.resolve("META-INF"))
            Files.writeString(
                metadata.resolve("rka-artifacts.sha256"),
                "${Hashes.sha256(Files.readAllBytes(target))}  rka-control.sh\n",
            )
        }

        fun replaceLastUptimeWithPrevious(delta: Long = 0) {
            val count = Files.readString(sentinel.resolve("count")).trim().toInt()
            val previous =
                Files.readAllLines(sentinel.resolve("samples/${count - 1}"))
                    .single { it.startsWith("uptime_ms=") }
                    .substringAfter('=')
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
