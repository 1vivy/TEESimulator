package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KsuNext330MetadataBridgeTest {
    @Test
    fun firstInstallReinjectsOnlyValidatedMetadataForTheInstalledManifest() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.pendingMetadataIsReinjected())
            assertTrue(fixture.pendingManifestVerifies())
        }
    }

    @Test
    fun existingLayoutReinjectsMetadataAfterKernelSuExcludesArchiveMetadata() {
        Fixture(kernelProfile = KernelProfile.KSU_NEXT_DUAL).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.pendingMetadataIsReinjected())
            assertTrue(fixture.pendingManifestVerifies())
        }
    }

    @Test
    fun invalidMetadataReceiptsFailBeforeKernelSuInstallationAndRollbackAbsentParents() {
        listOf(
                FixtureMutation.ARCHIVE_METADATA_MISSING,
                FixtureMutation.ARCHIVE_METADATA_DUPLICATE_PATH,
                FixtureMutation.ARCHIVE_METADATA_TRAVERSAL,
                FixtureMutation.ARCHIVE_METADATA_OVERSIZE,
                FixtureMutation.ARCHIVE_SOURCE_METADATA_MISMATCH,
            )
            .forEach { mutation ->
                Fixture(mutation, KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture ->
                    val result = fixture.run()

                    assertEquals(mutation.name, 4, result.exitCode)
                    assertTrue(mutation.name, fixture.moduleParentsAbsent())
                    assertTrue(mutation.name, fixture.metadataTransactionTempAbsent())
                }
            }
    }

    @Test
    fun tamperedArtifactManifestFailsInstalledFileVerificationAndRollsBackAbsentParents() {
        Fixture(
                FixtureMutation.ARCHIVE_ARTIFACT_METADATA_TAMPERED,
                KernelProfile.KSU_NEXT_FIRST_INSTALL,
            )
            .use { fixture ->
                val result = fixture.run()

                assertEquals(result.stderr, 4, result.exitCode)
                assertTrue(fixture.moduleParentsAbsent())
                assertTrue(fixture.metadataTransactionTempAbsent())
            }
    }

    @Test
    fun interruptionAfterReinjectionQuarantinesPendingMetadataAndRestoresAbsentParents() {
        Fixture(FixtureMutation.AFTER_METADATA, KernelProfile.KSU_NEXT_FIRST_INSTALL).use { fixture
            ->
            val result = fixture.run()

            assertEquals(result.stderr, 4, result.exitCode)
            assertTrue(fixture.moduleParentsAbsent())
            assertTrue(fixture.metadataTransactionTempAbsent())
        }
    }
}
