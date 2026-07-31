package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertTrue
import org.junit.Test

class ProvisioningSnapshotWriteGuardTest {
    @Test
    fun productionBytecodeContainsOnlyReadObservationCallsites() {
        ProvisioningSnapshotCallsiteGuard.requireReadOnly(
            ProvisioningSnapshot::class.java,
            ProvisioningSnapshot.Companion::class.java,
        )
    }

    @Test
    fun mutationDriverRejectsEveryRepresentativeWriteEscape() {
        val rejected = ProvisioningSnapshotCallsiteGuard.runMutationDriver()

        assertTrue(rejected.containsAll(ProvisioningSnapshotCallsiteGuard.requiredCategories))
    }
}
