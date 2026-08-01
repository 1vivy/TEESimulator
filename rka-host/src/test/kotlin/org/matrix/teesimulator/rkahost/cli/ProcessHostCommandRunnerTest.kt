package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.deleteIfExists
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessHostCommandRunnerTest {
    @Test
    fun drainsBothProcessPipesBeforeTheirCapacityCanBlockExit() =
        withExecutable(
            """
            #!/bin/sh
                        exec timeout 3 sh -c '
                            (head -c 262144 /dev/zero | tr "\\000" o) &
                            (head -c 262144 /dev/zero | tr "\\000" e >&2) &
                            wait
                        '
            """
                .trimIndent()
                .plus("\n")
        ) { executable ->
            val result =
                ProcessHostCommandRunner(executable.toString()).run(listOf("adb", "version"))

            assertEquals(0, result.exitCode)
            assertEquals(262_144, result.stdout.length)
            assertEquals(262_144, result.stderr.length)
            assertTrue(result.stdout.all { it == 'o' })
            assertTrue(result.stderr.all { it == 'e' })
        }

    @Test
    fun materializesRootScriptSoBackgroundDescendantCannotRetainTransportInput() =
        withExecutable(
            """
            #!/bin/sh
                        wire=${'$'}0.wire
                        trap 'rm -f "${'$'}0.wire"' 0 HUP INT TERM
                        cat > "${'$'}0.wire"
                        if grep -Fq 'rka_script=${'$'}(mktemp /data/local/tmp/rka-host-root.' "${'$'}0.wire" &&
                            grep -Fq 'sh "${'$'}rka_script" </dev/null' "${'$'}0.wire"; then
                            printf 'root-finished'
                            exit 0
                        fi
                        sleep 2
                        exit 124
            """
                .trimIndent()
                .plus("\n")
        ) { executable ->
            val result =
                ProcessHostCommandRunner(executable.toString())
                    .runRoot(
                        BoundSerial.parse("SERIAL_A"),
                        "( sleep 60 ) </dev/null >/dev/null 2>&1 3<&- &\nprintf root-finished\n",
                        listOf("start", "safe/value"),
                    )

            assertEquals(0, result.exitCode)
            assertEquals("root-finished", result.stdout)
            assertEquals("", result.stderr)
        }

    @Test
    fun boundsBothCapturedStreamsAndReturnsTypedNonzeroResult() =
        withExecutable(
            """
            #!/bin/sh
                        (head -c 1114112 /dev/zero | tr "\\000" o) &
                        (head -c 1114112 /dev/zero | tr "\\000" e >&2) &
                        wait
            """
                .trimIndent()
                .plus("\n")
        ) { executable ->
            val result =
                ProcessHostCommandRunner(executable.toString()).run(listOf("adb", "version"))

            assertEquals(74, result.exitCode)
            assertEquals(1_048_576, result.stdout.length)
            assertEquals(1_048_576 + "RKA_ADB_OUTPUT_TRUNCATED\n".length, result.stderr.length)
            assertTrue(result.stderr.endsWith("RKA_ADB_OUTPUT_TRUNCATED\n"))
        }

    private fun withExecutable(source: String, block: (Path) -> Unit) {
        val executable = Files.createTempFile("rka-process-runner-", ".sh")
        try {
            Files.writeString(executable, source)
            Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"))
            block(executable)
        } finally {
            executable.deleteIfExists()
            executable.resolveSibling("${executable.fileName}.wire").deleteIfExists()
        }
    }
}
