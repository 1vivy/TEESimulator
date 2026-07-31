package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KsuNext330AdapterTest {
    @Test
    fun donorOfficialManagerAndCandidateHeadlessManagerDeployWithoutPersistentKsud() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_DUAL).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(result.stdout.contains("\"result\":\"DEPLOYED_NO_REBOOT\""))
            assertTrue(fixture.trace().any { " READ_ONLY_PROBE_TRANSFER " in " $it " })
            assertFalse(fixture.trace().any { "pidof ksud" in it })
            assertTrue(fixture.hasKsuNextManagerSurfaceReceipts())
            assertTrue(fixture.probeArtifactsAbsent())
        }
    }

    @Test
    fun legacyProfileRetainsPersistentKsudNamespaceGate() {
        Fixture(kernelProfile = KernelProfile.LEGACY).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.trace().any { " preflight" in " $it " })
        }
    }

    @Test
    fun authorizationAndObservedProfileDriftFailBeforeArchiveTransfer() {
        val mutations =
            listOf(
                FixtureMutation.NEXT_APPID_ZERO,
                FixtureMutation.NEXT_APPID_AMBIGUOUS,
                FixtureMutation.NEXT_PACKAGES_MALICIOUS,
                FixtureMutation.NEXT_COMPONENT_WRONG,
                FixtureMutation.NEXT_SIGNING_WRONG,
                FixtureMutation.NEXT_HELP_DRIFT,
                FixtureMutation.NEXT_BINARY_DRIFT,
                FixtureMutation.NEXT_VERSION_DRIFT,
                FixtureMutation.NEXT_APPID_ERROR,
                FixtureMutation.NEXT_UID_MISMATCH,
                FixtureMutation.NEXT_BOOT_DRIFT,
            )
        mutations.forEach { mutation ->
            Fixture(mutation = mutation, kernelProfile = KernelProfile.KSU_NEXT_DUAL).use { fixture
                ->
                val result = fixture.run()

                assertEquals(mutation.name, 3, result.exitCode)
                assertFalse(
                    mutation.name,
                    fixture.trace().any {
                        "role-neutral-release.zip " in "$it " || " deploy " in " $it "
                    },
                )
                assertTrue(mutation.name, fixture.probeArtifactsAbsent())
            }
        }
    }
}
