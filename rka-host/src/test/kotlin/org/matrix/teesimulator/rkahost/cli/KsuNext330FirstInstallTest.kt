package org.matrix.teesimulator.rkahost.cli

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
}
