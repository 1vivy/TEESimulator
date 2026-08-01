package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SentinelInterruptionIntegrationTest {
    @Test
    fun standardWrapperFailsClosedAfterAmbiguousCommandInterruption() {
        val result = runScenario("transition-interruption")

        assertEquals(result.stderr, 2, result.exitCode)
        assertTrue(result.stderr, result.stderr.contains("RESULT=COMMAND_TRACE_INCOMPLETE"))
        assertTrue(result.stdout.isEmpty())
    }

    @Test
    fun repeatedInterruptionCannotResumeOrForgeSuccessfulLifecycle() {
        val result = runScenario("repeated-interruption")

        assertTrue("unexpected success: ${result.stdout}", result.exitCode != 0)
        assertFalse(result.stdout.contains("result=PASS"))
    }

    private fun runScenario(scenario: String): Result {
        val root = Files.createTempDirectory("sentinel-interruption-host-")
        return try {
            val host = root.resolve("rka-host")
            val java = Path.of(System.getProperty("java.home"), "bin", "java")
            val classpath = System.getProperty("java.class.path").replace("'", "'\\''")
            Files.writeString(
                host,
                "#!/bin/sh\nexec '$java' --enable-native-access=ALL-UNNAMED -cp '$classpath' ${HostCli::class.java.name} \"${'$'}@\"\n",
            )
            Files.setPosixFilePermissions(host, PosixFilePermissions.fromString("rwx------"))
            val script =
                Path.of(System.getProperty("user.dir"))
                    .resolve("src/test/resources/rka-sentinel-interruption-proof.sh")
            val process =
                ProcessBuilder("sh", script.toString(), scenario)
                    .apply { environment()["RKA_HOST_BIN"] = host.toString() }
                    .start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            Result(process.waitFor(), stdout, stderr)
        } finally {
            Files.walk(root).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private data class Result(val exitCode: Int, val stdout: String, val stderr: String)
}
