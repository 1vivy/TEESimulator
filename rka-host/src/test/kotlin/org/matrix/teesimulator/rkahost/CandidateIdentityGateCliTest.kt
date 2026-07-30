package org.matrix.teesimulator.rkahost

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CandidateIdentityGateCliTest {
    @Test
    fun injectedRootFailureSelectsProvenCompanion() {
        val decision =
            CandidateOwnerSelector.select(
                OwnerAttempt(CandidateTlsOwner.ROOT_DAEMON, false, "INTERCEPTOR_REENTRY")
            ) {
                OwnerAttempt(CandidateTlsOwner.CANDIDATE_COMPANION, true, null)
            }

        assertTrue(decision.proven)
        assertEquals(CandidateTlsOwner.CANDIDATE_COMPANION, decision.selectedOwner)
        assertFalse(decision.task6Marker)
    }

    @Test
    fun dualFailureIsTypedAndCreatesNoTask6Marker() {
        val decision =
            CandidateOwnerSelector.select(
                OwnerAttempt(CandidateTlsOwner.ROOT_DAEMON, false, "INTERCEPTOR_REENTRY")
            ) {
                OwnerAttempt(CandidateTlsOwner.CANDIDATE_COMPANION, false, "SOFTWARE_KEY")
            }

        assertFalse(decision.proven)
        assertNull(decision.selectedOwner)
        assertEquals("CANDIDATE_TLS_OWNER_UNPROVEN", decision.errorCode)
        assertEquals(
            listOf("ROOT_DAEMON:INTERCEPTOR_REENTRY", "CANDIDATE_COMPANION:SOFTWARE_KEY"),
            decision.failureCauses,
        )
        assertFalse(decision.task6Marker)
    }
}
