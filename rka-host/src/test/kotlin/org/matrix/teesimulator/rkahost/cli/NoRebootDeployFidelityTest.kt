package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NoRebootDeployFidelityTest {
    @Test
    fun realTlsHandshakeWritesTls13SpkiReceipt() {
        Fixture().use { fixture ->
            assertEquals(0, fixture.run().exitCode)

            assertTrue(fixture.hasTls13ProbeReceipts(expectedAttempts = 1))
            assertTrue(fixture.tlsServersStopped())
        }
    }

    @Test
    fun differentPeerCertificateRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.MISMATCH_CANDIDATE_PIN)
    }

    @Test
    fun tls12OnlyPeerRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.TLS12_ONLY)
    }

    @Test
    fun unavailablePeerRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.DIRECT_PROBE_UNAVAILABLE)
    }

    @Test
    fun staleDirectProfileRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.DIRECT_PROBE_STALE)
    }

    @Test
    fun rendererWithWrongZygoteParentRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.ZYGOTE_WRONG_PARENT)
    }

    @Test
    fun rendererWithNonZygoteIdentityRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.ZYGOTE_INVALID_IDENTITY)
    }

    @Test
    fun ambiguousWebViewZygoteRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.ZYGOTE_AMBIGUOUS)
    }

    @Test
    fun missingWebViewZygoteRollsBackTheLiveDeployment() {
        assertPairProbeRollback(FixtureMutation.ZYGOTE_MISSING)
    }

    private fun assertPairProbeRollback(mutation: FixtureMutation) {
        Fixture().use { fixture ->
            assertEquals(0, fixture.run().exitCode)
            val before = fixture.donorModuleSnapshot()

            val failed = fixture.runWithMutation(mutation)

            assertEquals(4, failed.exitCode)
            val after = fixture.donorModuleSnapshot()
            assertArrayEquals(before.bytes, after.bytes)
            assertEquals(before.permissions, after.permissions)
            assertEquals(before.modifiedMillis, after.modifiedMillis)
            assertTrue(fixture.donorBindPresent())
            assertTrue(fixture.donorRuntimeRunning())
            assertTrue(fixture.trace().count { " rollback " in " $it " } >= 2)
            assertTrue(fixture.tlsServersStopped())
        }
    }
}
