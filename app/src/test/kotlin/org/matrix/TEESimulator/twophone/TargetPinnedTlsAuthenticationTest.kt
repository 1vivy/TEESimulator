package org.matrix.TEESimulator.twophone

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

class TargetPinnedTlsAuthenticationTest {
    @Test
    fun pkixWrongDonorCertificateNeverReachesTheDonorBackend() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager(rig.profile(rig.foreignDonor, rig.target))
        try {
            assertFailsWith<TargetSessionException.PeerAuthentication> {
                manager.exchange(generate())
            }
            assertEquals(0, rig.backendInvocations())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    @Test
    fun pkixValidWrongDonorSpkiPinNeverReachesTheDonorBackend() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager(rig.profile(rig.donorDecoy, rig.target))
        try {
            assertFailsWith<TargetSessionException.DonorPinMismatch> {
                manager.exchange(generate())
            }
            assertEquals(0, rig.backendInvocations())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    @Test
    fun wrongTargetPinFailsBeforeConnectingAndInvokingTheBackend() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        try {
            assertFailsWith<PinnedJsseTargetContextException.InvalidIdentity> {
                rig.manager(rig.profile(rig.donor, rig.targetDecoy), rig.openedIdentity(rig.target))
            }
            assertEquals(0, rig.backendInvocations())
        } finally {
            rig.stopServer()
        }
    }

    @Test
    fun wrongClientCertificateIsRejectedByMutualTlsBeforeTheBackend() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val foreignProfile = rig.profile(rig.donor, rig.foreignTarget)
        val manager = rig.manager(foreignProfile, rig.openedIdentity(rig.foreignTarget))
        try {
            assertFailsWith<TargetSessionException.PeerAuthentication> {
                manager.exchange(generate())
            }
            assertEquals(0, rig.backendInvocations())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    private fun generate() =
        GenerateRequestPayload(
            java.util.UUID.randomUUID(),
            ByteArray(32) { 9 },
            byteArrayOf(1),
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            ),
        )
}
