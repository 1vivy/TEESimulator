package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbRootTransportTest {
    private val projectRoot = Path.of(System.getProperty("user.dir")).parent
    private val transport = projectRoot.resolve("scripts/rka-adb-root.sh")

    @Test
    fun productionDeployRoutesEveryRootActionThroughFixedArgvPrimitive() {
        val deploy = Files.readString(projectRoot.resolve("scripts/rka-deploy.sh"))

        assertTrue(deploy.contains("rka_adb_root_run \"\$adb_command\" \"\$serial\""))
        assertFalse(deploy.contains("shell su 0 sh -c"))
        assertFalse(deploy.contains("shell su 0 sh -s"))
        assertEquals(1, Regex("shell su 0 sh").findAll(Files.readString(transport)).count())
        listOf(
                "prepare-probe)",
                "cleanup-probe)",
                "prepare-upload)",
                "deploy)",
                "pair)",
                "rollback)",
            )
            .forEach { assertTrue(it, deploy.contains(it)) }
    }

    @Test
    fun splitRemoteShellArgumentsReproduceZeroOperandMkdir() = withFixture { fixture ->
        val target = fixture.root.resolve("split command target")
        val result =
            fixture.runFake(
                listOf(
                    "-s",
                    "SERIAL_A",
                    "shell",
                    "su",
                    "0",
                    "sh",
                    "-c",
                    "mkdir -p '$target' && chmod 700 '$target'",
                ),
                mapOf("RKA_FAKE_ADB_MODE" to "join"),
            )

        assertTrue(result.exitCode != 0)
        assertTrue(result.stderr.contains("missing operand"))
        assertFalse(Files.exists(target))
    }

    @Test
    fun stdinTransportPreservesFixedArgvAndExactScriptBytes() = withFixture { fixture ->
        val marker = fixture.root.resolve("must-not-execute")
        val script =
            "set -eu\nprintf '%s\\n' 'space value'\nprintf '%s\\n' \"\$(touch '$marker')\"\n# ; | & < >\n"
        val result = fixture.runTransport("SERIAL_A", script, listOf("mode", "safe/value"))

        assertEquals(0, result.exitCode)
        assertEquals("fixture stdout", result.stdout)
        assertEquals("fixture stderr", result.stderr)
        assertEquals("SERIAL_A\n", Files.readString(fixture.serialFile))
        assertArrayEquals(
            byteArrayOf(
                's'.code.toByte(),
                'u'.code.toByte(),
                0,
                '0'.code.toByte(),
                0,
                's'.code.toByte(),
                'h'.code.toByte(),
                0,
            ),
            Files.readAllBytes(fixture.argvFile),
        )
        val wire = Files.readString(fixture.stdinFile)
        val payload =
            wire
                .substringAfter("<<'RKA_ADB_ROOT_PAYLOAD_7D4C2A91'\n")
                .substringBefore("RKA_ADB_ROOT_PAYLOAD_7D4C2A91\n")
        assertEquals("set -- mode safe/value\n$script", payload)
        assertTrue(wire.contains("sh \"\$rka_script\" </dev/null"))
        assertFalse(Files.exists(marker))
    }

    @Test
    fun rejectsUnsealedEmptyAndOversizedInputsBeforeAdb() = withFixture { fixture ->
        val invalidSerial =
            fixture.runTransport("SERIAL_A;touch_bad", "printf safe\n", listOf("mode"))
        val empty = fixture.runTransport("SERIAL_A", "", listOf("mode"))
        val oversized = fixture.runOversizedTransport("SERIAL_A", 98304)
        val invalidArgument = fixture.runTransport("SERIAL_A", "printf safe\n", listOf("bad;arg"))
        val delimiter =
            fixture.runTransport(
                "SERIAL_A",
                "printf safe\nRKA_ADB_ROOT_PAYLOAD_7D4C2A91\nprintf unsafe\n",
                listOf("mode"),
            )

        listOf(invalidSerial, empty, oversized, invalidArgument, delimiter).forEach {
            assertEquals(64, it.exitCode)
            assertTrue(it.stderr.contains("RKA_ADB_ROOT_INPUT_INVALID"))
        }
        assertEquals(0, fixture.invocations())
    }

    @Test
    fun preservesNonzeroExitAndStderrWithoutEchoingScript() = withFixture { fixture ->
        val secret = "fixture-secret-must-not-log"
        val result =
            fixture.runTransport(
                "SERIAL_A",
                "printf '%s' '$secret' >/dev/null\n",
                listOf("mode"),
                mapOf(
                    "RKA_FAKE_EXIT" to "23",
                    "RKA_FAKE_STDOUT" to "remote-out",
                    "RKA_FAKE_STDERR" to "remote-error",
                ),
            )

        assertEquals(23, result.exitCode)
        assertEquals("remote-out", result.stdout)
        assertEquals("remote-error", result.stderr)
        assertFalse(result.stdout.contains(secret))
        assertFalse(result.stderr.contains(secret))
    }

    @Test
    fun rejectsTruncatedStdoutAndStderr() = withFixture { fixture ->
        listOf("overflow-stdout", "overflow-stderr", "overflow-both").forEach { mode ->
            val result =
                fixture.runTransport(
                    "SERIAL_A",
                    "printf safe\n",
                    listOf("mode"),
                    mapOf("RKA_FAKE_ADB_MODE" to mode),
                )
            assertEquals(74, result.exitCode)
            assertTrue(result.stderr.endsWith("RKA_ADB_ROOT_OUTPUT_TRUNCATED\n"))
            assertTrue(result.stdout.length <= 1048576)
            assertTrue(result.stderr.length <= 1048576 + 31)
        }
    }

    private fun withFixture(block: (TransportFixture) -> Unit) {
        val fixture = TransportFixture(projectRoot, transport)
        try {
            block(fixture)
        } finally {
            fixture.close()
        }
    }
}

private data class TransportResult(val exitCode: Int, val stdout: String, val stderr: String)

private class TransportFixture(private val projectRoot: Path, private val transport: Path) {
    val root: Path = Files.createTempDirectory("rka-adb-root-contract-")
    val argvFile: Path = root.resolve("argv.bin")
    val stdinFile: Path = root.resolve("stdin.bin")
    val serialFile: Path = root.resolve("serial.txt")
    private val invocationFile: Path = root.resolve("invocations")
    private val fakeAdb = root.resolve("adb")
    private val fakeBin = root.resolve("bin")

    init {
        Files.writeString(
            fakeAdb,
            checkNotNull(javaClass.getResource("/rka-adb-root-contract.sh")).readText(),
        )
        Files.setPosixFilePermissions(fakeAdb, PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(fakeBin)
        val fakeSu = fakeBin.resolve("su")
        Files.writeString(fakeSu, "#!/bin/sh\nshift\nexec \"\$@\"\n")
        Files.setPosixFilePermissions(fakeSu, PosixFilePermissions.fromString("rwx------"))
    }

    fun runFake(arguments: List<String>, environment: Map<String, String>): TransportResult =
        run(listOf(fakeAdb.toString()) + arguments, environment)

    fun runTransport(
        serial: String,
        script: String,
        arguments: List<String>,
        environment: Map<String, String> = emptyMap(),
    ): TransportResult {
        val shell = "source \"\$1\"; shift; rka_adb_root_run \"\$@\""
        val command =
            listOf(
                "bash",
                "-c",
                shell,
                "bash",
                transport.toString(),
                fakeAdb.toString(),
                serial,
                script,
            ) + arguments
        return run(command, environment)
    }

    fun runOversizedTransport(serial: String, bytes: Int): TransportResult {
        val shell =
            "source \"\$1\"; payload=\$(head -c \"\$4\" /dev/zero | tr '\\0' x); " +
                "payload+=\$'\\n'; rka_adb_root_run \"\$2\" \"\$3\" \"\$payload\" mode"
        return run(
            listOf(
                "bash",
                "-c",
                shell,
                "bash",
                transport.toString(),
                fakeAdb.toString(),
                serial,
                bytes.toString(),
            ),
            emptyMap(),
        )
    }

    fun invocations(): Int =
        if (Files.exists(invocationFile)) Files.readAllLines(invocationFile).size else 0

    fun close() {
        Files.walk(root).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
    }

    private fun run(command: List<String>, overrides: Map<String, String>): TransportResult {
        val process =
            ProcessBuilder(command)
                .directory(projectRoot.toFile())
                .apply {
                    environment()["RKA_FAKE_ARGV_FILE"] = argvFile.toString()
                    environment()["RKA_FAKE_STDIN_FILE"] = stdinFile.toString()
                    environment()["RKA_FAKE_SERIAL_FILE"] = serialFile.toString()
                    environment()["RKA_FAKE_INVOCATION_FILE"] = invocationFile.toString()
                    environment()["RKA_FAKE_SU_BIN"] = fakeBin.toString()
                    environment()["RKA_FAKE_STDOUT"] = "fixture stdout"
                    environment()["RKA_FAKE_STDERR"] = "fixture stderr"
                    environment().putAll(overrides)
                }
                .start()
        val stdout =
            CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderr =
            CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        check(process.waitFor(20, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            "transport fixture timed out"
        }
        return TransportResult(process.exitValue(), stdout.get(), stderr.get())
    }
}
