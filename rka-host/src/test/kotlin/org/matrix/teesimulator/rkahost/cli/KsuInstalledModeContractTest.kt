package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class KsuInstalledModeContractTest {
    @Test
    fun faithfulKernelSuExtractionRestoresExecutableModesBeforeSetRole() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.pendingInstalledModesAreExecutable())
        }
    }

    @Test
    fun installedModeBoundaryRejectsMissingFailedOrDriftedPermissionAssignment() {
        listOf(
                FixtureMutation.KSU_CUSTOMIZE_MISSING,
                FixtureMutation.KSU_EXECUTABLE_MODE,
                FixtureMutation.KSU_ORDINARY_MODE,
                FixtureMutation.KSU_DIRECTORY_MODE,
                FixtureMutation.KSU_WRONG_OWNER,
                FixtureMutation.KSU_SYMLINK_TYPE,
            )
            .forEach { mutation ->
                Fixture(mutation, KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
                    val result = fixture.run()

                    assertEquals(mutation.name, 4, result.exitCode)
                    assertTrue(mutation.name, result.stderr.contains("RKA_INSTALLED_MODE_CONTRACT"))
                }
            }
    }

    @Test
    fun failedCustomizeHookStopsInstallationBeforeAnyModuleExecutable() {
        Fixture(FixtureMutation.KSU_CUSTOMIZE_FAILURE, KernelProfile.KSU_NEXT_FIRST_INSTALL).use {
            fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 4, result.exitCode)
            assertTrue(result.stderr, !result.stderr.contains("Permission denied"))
        }
    }

    @Test
    fun packagedZipAdvancesBeyondSetRoleAfterFaithfulKernelSuInstall() {
        val packageZip = System.getenv("RKA_PACKAGE_ZIP")
        assumeTrue(!packageZip.isNullOrEmpty())
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            fixture.replaceArchive(Path.of(packageZip))

            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.pendingInstalledModesAreExecutable())
            assertTrue(result.stdout.contains("\"result\":\"DEPLOYED_NO_REBOOT\""))
        }
    }

    @Test
    fun packagedZipWithoutCustomizeFailsOnInstalledModeContract() {
        val packageZip = System.getenv("RKA_PACKAGE_ZIP")
        assumeTrue(!packageZip.isNullOrEmpty())
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            fixture.replaceArchive(Path.of(packageZip), omitCustomize = true)

            val result = fixture.run()

            assertEquals(result.stderr, 4, result.exitCode)
            assertTrue(result.stderr, result.stderr.contains("RKA_INSTALLED_MODE_CONTRACT"))
        }
    }
}
