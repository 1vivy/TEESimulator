package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Comparator
import kotlin.io.path.deleteIfExists
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
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
    fun materializedRootScriptReturnsWhileDirectInputWaitsForInheritedScriptDescriptor() =
        withRemoteShell(descriptorAwareRemoteShell()) { executable, remote ->
            val script =
                """
                ( sleep 60 ) 8<&0 </dev/null >/dev/null 2>&1 3<&- &
                printf '%s\n' "${'$'}!" > /data/local/tmp/descendant.pid
                sleep 0.1
                printf root-finished
                """
                    .trimIndent()
                    .plus("\n")
            val legacyFailure =
                assertThrows(HostCliException::class.java) {
                    ProcessHostCommandRunner(
                            executable.toString(),
                            script.toByteArray(),
                            Duration.ofMillis(500),
                        )
                        .run(listOf("adb", "-s", "SERIAL_A", "shell", "su", "0", "sh"))
                }

            assertEquals("ADB_TIMEOUT", legacyFailure.message)
            assertEventuallyDead(readPid(remote.resolve("descendant.pid")))

            Files.delete(remote.resolve("descendant.pid"))
            val result =
                ProcessHostCommandRunner(
                        executable.toString(),
                        commandTimeout = Duration.ofSeconds(2),
                    )
                    .runRoot(BoundSerial.parse("SERIAL_A"), script, listOf("start", "safe/value"))

            assertEquals(0, result.exitCode)
            assertEquals("root-finished", result.stdout)
            assertEquals("", result.stderr)
            terminateExactProcess(readPid(remote.resolve("descendant.pid")))
        }

    @Test
    fun timeoutTerminatesAndReapsOnlyItsLocalProcessTree() =
        withExecutable(
            """
            #!/bin/sh
            printf '%s\n' "${'$'}${'$'}" > "${'$'}0.root.pid"
            sleep 60 &
            printf '%s\n' "${'$'}!" > "${'$'}0.child.pid"
            wait
            """
                .trimIndent()
                .plus("\n")
        ) { executable ->
            val failure =
                assertThrows(HostCliException::class.java) {
                    ProcessHostCommandRunner(
                            executable.toString(),
                            commandTimeout = Duration.ofMillis(500),
                        )
                        .run(listOf("adb", "version"))
                }

            assertEquals("ADB_TIMEOUT", failure.message)
            assertEventuallyDead(
                readPid(executable.resolveSibling("${executable.fileName}.root.pid"))
            )
            assertEventuallyDead(
                readPid(executable.resolveSibling("${executable.fileName}.child.pid"))
            )
        }

    @Test
    fun rootTimeoutLeavesNoMaterializedPathOrTaskProcess() =
        withRemoteShell(streamingRemoteShell()) { executable, remote ->
            val failure =
                assertThrows(HostCliException::class.java) {
                    ProcessHostCommandRunner(
                            executable.toString(),
                            commandTimeout = Duration.ofMillis(500),
                        )
                        .runRoot(
                            BoundSerial.parse("SERIAL_A"),
                            "printf '%s\\n' \"${'$'}${'$'}\" > /data/local/tmp/task.pid\n" +
                                "sleep 60\n",
                            listOf("start", "safe/value"),
                        )
                }

            assertEquals("ADB_TIMEOUT", failure.message)
            assertEventuallyDead(readPid(remote.resolve("task.pid")))
            Files.list(remote).use { paths ->
                assertFalse(paths.anyMatch { it.fileName.toString().startsWith("rka-host-root.") })
            }
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

    private fun descriptorAwareRemoteShell(): String =
        """
        #!/bin/sh
        remote=${'$'}0.remote
        mkdir -p "${'$'}remote"
        shift 2
        sed "s#/data/local/tmp#${'$'}remote#g" | sh
        status=${'$'}?
        if [ -s "${'$'}remote/descendant.pid" ]; then
            descendant=${'$'}(cat "${'$'}remote/descendant.pid")
            inherited_pipe=false
            for descriptor in /proc/"${'$'}descendant"/fd/*; do
                case "${'$'}(readlink "${'$'}descriptor" 2>/dev/null)" in
                    pipe:*) inherited_pipe=true ;;
                esac
            done
            if [ "${'$'}inherited_pipe" = true ]; then
                while kill -0 "${'$'}descendant" 2>/dev/null; do sleep 1; done
            fi
        fi
        exit "${'$'}status"
        """
            .trimIndent()
            .plus("\n")

    private fun streamingRemoteShell(): String =
        """
        #!/bin/sh
        remote=${'$'}0.remote
        mkdir -p "${'$'}remote"
        shift 2
        sed "s#/data/local/tmp#${'$'}remote#g" | sh
        """
            .trimIndent()
            .plus("\n")

    private fun withExecutable(source: String, block: (Path) -> Unit) {
        val executable = Files.createTempFile("rka-process-runner-", ".sh")
        try {
            Files.writeString(executable, source)
            Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"))
            block(executable)
        } finally {
            listOf("root.pid", "child.pid").forEach { suffix ->
                val pidFile = executable.resolveSibling("${executable.fileName}.$suffix")
                if (Files.exists(pidFile)) {
                    terminateExactProcess(readPid(pidFile))
                    pidFile.deleteIfExists()
                }
            }
            executable.deleteIfExists()
            executable.resolveSibling("${executable.fileName}.wire").deleteIfExists()
        }
    }

    private fun withRemoteShell(source: String, block: (Path, Path) -> Unit) {
        withExecutable(source) { executable ->
            val remote = executable.resolveSibling("${executable.fileName}.remote")
            Files.createDirectory(remote)
            try {
                block(executable, remote)
            } finally {
                listOf("descendant.pid", "task.pid").forEach { name ->
                    val pidFile = remote.resolve(name)
                    if (Files.exists(pidFile)) terminateExactProcess(readPid(pidFile))
                }
                Files.walk(remote).use { paths ->
                    paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
                }
            }
        }
    }

    private fun readPid(path: Path): Long = Files.readString(path).trim().toLong()

    private fun assertEventuallyDead(pid: Long) {
        repeat(100) {
            if (!ProcessHandle.of(pid).map { it.isAlive }.orElse(false)) return
            Thread.sleep(10)
        }
        assertFalse(
            "task-owned process $pid survived",
            ProcessHandle.of(pid).map { it.isAlive }.orElse(false),
        )
    }

    private fun terminateExactProcess(pid: Long) {
        ProcessHandle.of(pid).filter { it.isAlive }.ifPresent { it.destroyForcibly() }
    }
}
