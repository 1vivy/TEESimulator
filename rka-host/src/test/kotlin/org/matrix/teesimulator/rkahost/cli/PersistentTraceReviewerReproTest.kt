package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistentTraceReviewerReproTest {
    private val project = Path.of(System.getProperty("user.dir")).parent

    @Test
    fun productionJournalUsesAtomicMoveOwnerChecksAndDurableTerminalStates() {
        val journal =
            Files.readString(
                project.resolve(
                    "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/cli/PersistentAdbTrace.kt"
                )
            ) +
                Files.readString(
                    project.resolve(
                        "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/cli/TracePersistence.kt"
                    )
                )
        val host =
            Files.readString(
                project.resolve(
                    "rka-host/src/main/kotlin/org/matrix/teesimulator/rkahost/cli/HostCli.kt"
                )
            )

        assertTrue(journal.contains("StandardCopyOption.ATOMIC_MOVE"))
        assertTrue(journal.contains("trustedOwner"))
        assertTrue(journal.contains("TraceLifecycleState.SEALED"))
        assertFalse(host.contains("Files.deleteIfExists(tracePath)"))
    }

    @Test
    fun authoritativeLifecycleNamesInstalledDistributionAndRepositoryDeploy() {
        val lifecycle =
            Files.readString(
                project.resolve(
                    "rka-host/src/test/kotlin/org/matrix/teesimulator/rkahost/cli/AuthoritativeShippedTraceLifecycleTest.kt"
                )
            ) +
                Files.readString(
                    project.resolve(
                        "rka-host/src/test/kotlin/org/matrix/teesimulator/rkahost/cli/NoRebootDeployFixture.kt"
                    )
                )

        assertTrue(lifecycle.contains("build/install/rka-host/bin/rka-host"))
        assertTrue(lifecycle.contains("scripts/rka-deploy.sh"))
        assertFalse(lifecycle.contains("hostLauncher()"))
        assertFalse(lifecycle.contains("runtime.resolve(\"rka-deploy.sh\")"))
    }

    @Test
    fun adversarialCoverageNamesRealFilesystemAndProcessActions() {
        val tests =
            Files.readString(
                project.resolve(
                    "rka-host/src/test/kotlin/org/matrix/teesimulator/rkahost/cli/PersistentAdbTraceTest.kt"
                )
            ) +
                Files.readString(
                    project.resolve(
                        "rka-host/src/test/kotlin/org/matrix/teesimulator/rkahost/cli/PersistentTraceMultiProcessIntegrationTest.kt"
                    )
                )

        assertTrue(tests.contains("actualSymlinkIsRejected"))
        assertTrue(tests.contains("wrongOwnerIsRejectedByInjectedIdentitySeam"))
        assertTrue(tests.contains("atomicRenameFailureLeavesNoAmbiguousContinuation"))
        assertTrue(tests.contains("fsyncFailureLeavesNoAmbiguousContinuation"))
        assertTrue(tests.contains("lastAllowedEventAndByteBoundaryPassAndNextAreRejected"))
        assertTrue(tests.contains("separateInstalledCliProcessesContendOnFilesystemLock"))
    }
}
