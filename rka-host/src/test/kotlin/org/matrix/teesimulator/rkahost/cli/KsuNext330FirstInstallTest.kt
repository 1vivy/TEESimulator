package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KsuNext330FirstInstallTest {
    @Test
    fun pairedAbsentParentsInstallWithoutPhaseAMutationOrSystemOpenSsl() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL_NO_OPENSSL).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.firstInstallFacts(), fixture.hasFirstInstallReceipts())
            assertTrue(fixture.trace().none { " preflight " in " $it " && " mkdir " in " $it " })
            assertFalse(fixture.trace().any { "openssl" in it })
        }
    }

    @Test
    fun pairedEmptyParentsInstallAsTypedFirstInstall() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL_EMPTY).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(
                fixture.firstInstallFacts(),
                fixture.hasFirstInstallReceipts("FIRST_INSTALL_EMPTY_LAYOUT"),
            )
        }
    }

    @Test
    fun unrelatedExistingParentsInstallAsTypedFirstInstall() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL_EXISTING_PARENTS).use { fixture
            ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(
                fixture.firstInstallFacts(),
                fixture.hasFirstInstallReceipts(
                    mapOf(
                        "DONOR_A" to "FIRST_INSTALL_EMPTY_LAYOUT",
                        "CANDIDATE_B" to "FIRST_INSTALL_EXISTING_PARENTS",
                    )
                ),
            )
        }
    }

    @Test
    fun emptyRootOwnedPrivatePidDirectoriesPermitFirstInstall() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            fixture.preparePidDirectories()

            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.firstInstallFacts(), fixture.hasFirstInstallReceipts())
        }
    }

    @Test
    fun populatedOrSymlinkPidDirectoriesFailBeforeTransfer() {
        listOf("populated", "symlink").forEach { layout ->
            Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
                fixture.preparePidDirectories(layout)

                val result = fixture.run()

                assertEquals(layout, 3, result.exitCode)
                assertFalse(layout, fixture.trace().any { " push " in " $it " })
            }
        }
    }

    @Test
    fun nonPrivatePidDirectoriesFailBeforeTransfer() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            fixture.preparePidDirectories("world-readable")

            val result = fixture.run()

            assertEquals(result.stderr, 3, result.exitCode)
            assertFalse(fixture.trace().any { " push " in " $it " })
        }
    }

    @Test
    fun failedPairRestoresPairedAbsentParents() {
        Fixture(
                mutation = FixtureMutation.TLS12_ONLY,
                kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL,
            )
            .use { fixture ->
                assertEquals(4, fixture.run().exitCode)
                assertTrue(fixture.moduleParentsAbsent())
            }
    }

    @Test
    fun interruptionAfterSingleInstallRestoresPairedAbsentParents() {
        Fixture(
                mutation = FixtureMutation.AFTER_INSTALL,
                kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL,
            )
            .use { fixture ->
                assertEquals(4, fixture.run().exitCode)
                assertTrue(fixture.moduleParentsAbsent())
            }
    }

    @Test
    fun interruptionAfterInstallPreservesExistingFirstInstallParents() {
        Fixture(
                mutation = FixtureMutation.AFTER_INSTALL,
                kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL_EXISTING_PARENTS,
            )
            .use { fixture ->
                assertEquals(4, fixture.run().exitCode)
                assertTrue(fixture.firstInstallParentContentsRestored())
            }
    }

    @Test
    fun rollbackAfterSuccessfulFirstInstallRebuildsPreexistingDerivedViews() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL_EXISTING_PARENTS).use { fixture
            ->
            assertEquals(0, fixture.run().exitCode)

            val rollback = fixture.rollbackDonorAgain()

            assertEquals(rollback.stderr, 0, rollback.exitCode)
        }
    }

    @Test
    fun failedInstallWithOnlyOneCreatedParentRestoresPairedAbsence() {
        listOf(
                FixtureMutation.INSTALL_ONLY_MODULES_PARENT,
                FixtureMutation.INSTALL_ONLY_UPDATE_PARENT,
            )
            .forEach { mutation ->
                Fixture(mutation, KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
                    assertEquals(mutation.name, 4, fixture.run().exitCode)
                    assertTrue(mutation.name, fixture.moduleParentsAbsent())
                }
            }
    }

    @Test
    fun malformedOrPartiallyPresentLayoutsFailBeforeTransfer() {
        val mutations =
            listOf(
                FixtureMutation.NEXT_LAYOUT_ONE_PARENT,
                FixtureMutation.NEXT_LAYOUT_TARGET_FILE,
                FixtureMutation.NEXT_LAYOUT_FILE,
                FixtureMutation.NEXT_LAYOUT_SYMLINK,
                FixtureMutation.NEXT_LAYOUT_HIDDEN_MOUNT,
            )
        mutations.forEach { mutation ->
            Fixture(mutation, KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
                val result = fixture.run()

                assertEquals(mutation.name, 3, result.exitCode)
                assertFalse(mutation.name, fixture.trace().any { " push " in " $it " })
            }
        }
    }

    @Test
    fun legacyProfileRejectsPairedAbsentParentsBeforeTransfer() {
        Fixture(kernelProfile = KernelProfile.LEGACY_FIRST_INSTALL).use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertFalse(fixture.trace().any { " push " in " $it " })
        }
    }

    private fun Fixture.preparePidDirectories(layout: String = "empty") {
        listOf("DONOR_A", "CANDIDATE_B").forEach { serial ->
            val pidDirectory = devices.resolve("$serial/root/data/adb/teesimulator-rka/run/pids")
            Files.createDirectories(pidDirectory.parent)
            when (layout) {
                "empty" -> Files.createDirectory(pidDirectory)
                "populated" -> {
                    Files.createDirectory(pidDirectory)
                    Files.writeString(pidDirectory.resolve("broker.pid"), "1 1 1\n")
                }
                "symlink" -> {
                    val target = devices.resolve("$serial/root/tmp/pid-target")
                    Files.createDirectories(target)
                    Files.createSymbolicLink(pidDirectory, Path.of("/tmp/pid-target"))
                }
                "world-readable" -> Files.createDirectory(pidDirectory)
                else -> error("unknown PID layout: $layout")
            }
            if (!Files.isSymbolicLink(pidDirectory)) {
                Files.setPosixFilePermissions(
                    pidDirectory,
                    PosixFilePermissions.fromString(
                        if (layout == "world-readable") "rwxr-xr-x" else "rwx------"
                    ),
                )
            }
        }
    }
}
