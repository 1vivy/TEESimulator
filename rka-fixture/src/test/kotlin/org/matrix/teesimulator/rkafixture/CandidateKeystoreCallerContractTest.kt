package org.matrix.teesimulator.rkafixture

import org.junit.Assert.assertThrows
import org.junit.Test

class CandidateKeystoreCallerContractTest {
    @Test
    fun rejectsAliasesOutsideTheCallerFixtureNamespace() {
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKeystoreCaller.generateEcSigningKey("outside_fixture_namespace")
        }
    }
}
