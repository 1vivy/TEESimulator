package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertEquals
import org.junit.Test

class ProvisioningSnapshotWriteGuardTest {
    @Test
    fun productionBytecodeContainsOnlyReadObservationCallsites() {
        assertEquals(
            emptySet<String>(),
            ProvisioningSnapshotCallsiteGuard.detectedCategories(
                ProvisioningSnapshot::class.java,
                ProvisioningSnapshot.Companion::class.java,
            ),
        )
        ProvisioningSnapshotCallsiteGuard.requireReadOnly(
            ProvisioningSnapshot::class.java,
            ProvisioningSnapshot.Companion::class.java,
        )
    }

    @Test
    fun mutationDriverRejectsEveryRepresentativeWriteEscape() {
        val rejected = ProvisioningSnapshotCallsiteGuard.runMutationDriver()

        assertEquals(ProvisioningSnapshotCallsiteGuard.requiredCategories, rejected.keys)
        rejected.forEach { (category, detected) -> assertEquals(setOf(category), detected) }
    }
}
