package org.matrix.TEESimulator.rka.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.BrokerDeadline

class ProvisioningBridgeDeadlineTest {
    @Test
    fun directCandidateAndProvisioningBudgetsRemainSeparatelyBounded() {
        assertEquals(5_000L, BridgeLimits.DEADLINE_MILLIS)
        assertEquals(15_000L, BridgeLimits.CANDIDATE_DEADLINE_MILLIS)
        assertEquals(30_000L, BridgeLimits.DONOR_DEADLINE_MILLIS)
        assertTrue(BridgeLimits.CANDIDATE_DEADLINE_MILLIS < BridgeLimits.DONOR_DEADLINE_MILLIS)
        assertEquals(BridgeLimits.DONOR_DEADLINE_MILLIS, BridgeLimits.MAX_DEADLINE_MILLIS)
        assertTrue(BrokerDeadline.MAX_MILLIS >= BridgeLimits.DONOR_DEADLINE_MILLIS)
    }
}
