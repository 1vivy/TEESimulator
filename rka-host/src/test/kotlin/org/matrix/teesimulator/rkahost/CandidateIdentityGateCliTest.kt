package org.matrix.teesimulator.rkahost

import org.junit.Assert.assertEquals
import org.junit.Test

class CandidateIdentityGateCliTest {
    @Test
    fun noArgumentInvocationRetainsCallerOnlyHostSurface() {
        assertEquals(0, CandidateIdentityGateCli.run(emptyArray()))
    }

    @Test
    fun argumentsDoNotActivateADeviceWorkflow() {
        assertEquals(1, CandidateIdentityGateCli.run(arrayOf("candidate-identity-gate")))
    }
}
