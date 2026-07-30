package org.matrix.teesimulator.rkafixture

import java.util.UUID
import junit.framework.TestCase

class CandidateKeystoreCallerTest : TestCase() {
    fun testDirectCallerGeneratesNonExportableEcKey() {
        val alias = "teesim_rka_fixture_${UUID.randomUUID().toString().replace('-', '_')}"
        try {
            val material = CandidateKeystoreCaller.generateEcSigningKey(alias)

            assertNull(material.privateKey.encoded)
            assertEquals("EC", material.privateKey.algorithm)
            assertEquals("EC", material.publicKey.algorithm)
        } finally {
            CandidateKeystoreCaller.delete(alias)
        }
    }
}
