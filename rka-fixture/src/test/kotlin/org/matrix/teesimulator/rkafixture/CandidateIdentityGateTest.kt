package org.matrix.teesimulator.rkafixture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CandidateIdentityGateTest {
    @Test
    fun orderedStateMachineSelectsExactlyOneProvenOwner() {
        val gateClass = Class.forName("org.matrix.teesimulator.rkafixture.CandidateIdentityGate")
        val states =
            gateClass.getMethod("requiredStateNames").invoke(null).let { result ->
                @Suppress("UNCHECKED_CAST")
                result as List<String>
            }

        assertEquals(
            listOf(
                "IDENTITY_CREATED",
                "PUBLIC_TRUST_STAGED",
                "PROFILE_STAGED",
                "LISTENER_READY",
                "TLS_PROVED",
                "ACTIVE",
            ),
            states,
        )
    }

    @Test
    fun rejectsUnprovenOwners() {
        val gateClass = Class.forName("org.matrix.teesimulator.rkafixture.CandidateIdentityGate")
        val evaluate =
            gateClass.getMethod(
                "evaluateInjected",
                Boolean::class.javaPrimitiveType,
                String::class.java,
                Boolean::class.javaPrimitiveType,
                String::class.java,
            )
        val result = evaluate.invoke(null, false, "INTERCEPTOR_REENTRY", false, "SOFTWARE_KEY")
        val resultClass = result.javaClass

        assertFalse(resultClass.getMethod("getProven").invoke(result) as Boolean)
        assertEquals(
            "CANDIDATE_TLS_OWNER_UNPROVEN",
            resultClass.getMethod("getErrorCode").invoke(result),
        )
        assertEquals(null, resultClass.getMethod("getSelectedOwner").invoke(result))
        assertFalse(resultClass.getMethod("getTask6Marker").invoke(result) as Boolean)
        assertTrue(
            (resultClass.getMethod("getFailureCauses").invoke(result) as List<*>).containsAll(
                listOf("ROOT_DAEMON:INTERCEPTOR_REENTRY", "CANDIDATE_COMPANION:SOFTWARE_KEY")
            )
        )
    }

    @Test
    fun rootRecursionFallsBackToCompanion() {
        val result =
            CandidateIdentityGate.evaluateInjected(
                rootProven = false,
                rootFailure = "INTERCEPTOR_REENTRY",
                companionProven = true,
                companionFailure = "",
            )

        assertTrue(result.proven)
        assertEquals("CANDIDATE_COMPANION", result.selectedOwner)
        assertFalse(result.task6Marker)
    }

    @Test
    fun softwareAndWatchdogProofsAreRejected() {
        val valid =
            proof(owner = CandidateIdentityOwner.ROOT_DAEMON, candidateLocalGenerateCount = 1)
        assertTrue(valid.isProven())
        assertFalse(valid.copy(teeSecurityLevel = false).isProven())
        assertFalse(valid.copy(insideSecurityHardware = false).isProven())
        assertFalse(valid.copy(watchdogLatencyMillis = 30_000).isProven())
        assertFalse(valid.copy(interceptorReentryCount = 1).isProven())
        assertFalse(valid.copy(candidateLocalGenerateCount = 2).isProven())
        assertFalse(valid.copy(rebootReceipt = false).isProven())
    }

    @Test
    fun fallbackBinderDeathClosesExactlyOnce() {
        var closes = 0
        val session = ClientOwnedCandidateSession { closes++ }

        session.linkToClientDeath()
        session.clientDied()
        session.close()

        assertTrue(session.deathLinked)
        assertEquals(1, session.closeCount)
        assertEquals(1, closes)
    }

    private fun proof(owner: CandidateIdentityOwner, candidateLocalGenerateCount: Int) =
        CandidateOwnerProof(
            owner = owner,
            states = CandidateGateState.entries,
            privateKeyEncodedNull = true,
            insideSecurityHardware = true,
            teeSecurityLevel = true,
            ecP256 = true,
            tlsProtocol = "TLSv1.3",
            clientCertificateRequired = true,
            pinnedPeer = true,
            interceptorReentryCount = 0,
            candidateLocalGenerateCount = candidateLocalGenerateCount,
            watchdogLatencyMillis = 10,
            watchdogLimitMillis = 30_000,
            rebootReceipt = true,
        )
}
