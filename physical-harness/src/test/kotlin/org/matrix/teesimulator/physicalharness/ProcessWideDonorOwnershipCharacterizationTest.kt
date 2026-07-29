package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class ProcessWideDonorOwnershipCharacterizationTest {
    @Test
    fun separateRuntimeOwnersReuseOneProcessWideDonorProcess() {
        // Given: two runtime owners in the same donor process.
        val sharedProcessHolder = DonorProcessHolder<TestDonorProcess>()
        val firstOwner = DonorRuntimeTestRig(processHolder = sharedProcessHolder)
        val secondOwner = DonorRuntimeTestRig(processHolder = sharedProcessHolder)

        // When: each owner starts its server.
        firstOwner.owner.start("approved.profile", Instant.now())
        secondOwner.owner.start("approved.profile", Instant.now())

        // Then: only the first owner creates the donor process.
        assertEquals(1, firstOwner.processCalls.get())
        assertEquals(0, secondOwner.processCalls.get())
    }
}
