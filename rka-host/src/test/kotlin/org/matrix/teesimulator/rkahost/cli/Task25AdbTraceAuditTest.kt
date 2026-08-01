package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Task25AdbTraceAuditTest {
    @Test
    fun productionTask25AdbExecutionHasOneAuditedProcessAndDeployAdapterSeam() {
        val root = Path.of(System.getProperty("user.dir")).parent
        val orchestration =
            Files.readString(
                root.resolve(
                    "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/cli/HostOrchestration.kt"
                )
            )
        val runtime =
            Files.readString(
                root.resolve(
                    "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/cli/HostRuntimeTypes.kt"
                )
            )
        val deploy = Files.readString(root.resolve("scripts/rka-deploy.sh"))
        val transport = Files.readString(root.resolve("scripts/rka-adb-root.sh"))
        val adapter = Files.readString(root.resolve("scripts/rka-traced-adb.sh"))
        val diagnosticRelay =
            Files.readString(
                root.resolve(
                    "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/UsbHostRelayTransport.kt"
                )
            )

        assertFalse(orchestration.contains("ProcessBuilder"))
        assertEqualsOne(runtime, "ProcessBuilder(liveArgv).start()")
        assertFalse(Regex("(^|[;&|]\\s*)adb\\s+-s", RegexOption.MULTILINE).containsMatchIn(deploy))
        assertFalse(
            Regex("(^|[;&|]\\s*)adb\\s+-s", RegexOption.MULTILINE).containsMatchIn(transport)
        )
        assertTrue(deploy.contains("ADB_TRACE_REQUIRED"))
        assertTrue(adapter.contains("trace-adb"))
        assertTrue(diagnosticRelay.contains("DIAGNOSTIC_USB_RELAY"))
        assertFalse(orchestration.contains("UsbHostRelay"))
    }

    private fun assertEqualsOne(raw: String, token: String) {
        assertTrue(raw.windowed(token.length).count { it == token } == 1)
    }
}
