package org.matrix.teesimulator.rkahost

import java.time.Duration
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectProfileTest {
    @Test
    fun selectsPinnedDirectEndpoint() {
        val lan = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val tailscale = profile(8, DirectPath.TAILSCALE, "100.88.0.8", "100.88.0.9", 0x22)

        assertEquals("192.168.50.8", lan.connect.host)
        assertEquals("100.88.0.8", tailscale.connect.host)
        assertArrayEquals(ByteArray(32) { 0x11 }, lan.peerSpki())
        assertSame(lan, DirectProfileSelector.select(listOf(lan, tailscale), DirectPath.LAN))
        assertSame(
            tailscale,
            DirectProfileSelector.select(listOf(lan, tailscale), DirectPath.TAILSCALE),
        )
    }

    @Test
    fun rejectsNonCanonicalEndpointsWildcardInterfacesAndUnboundedTimeouts() {
        assertFailure { DirectEndpoint("DONOR.tailnet.ts.net", 8443) }
        assertFailure { DirectEndpoint("192.168.050.8", 8443) }
        assertFailure {
            DirectProfile.create(
                7,
                DirectPath.LAN,
                DirectEndpoint("192.168.50.8", 8443),
                "0.0.0.0",
                ByteArray(32),
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
            )
        }
        assertFailure {
            DirectProfile.create(
                7,
                DirectPath.LAN,
                DirectEndpoint("192.168.50.8", 8443),
                "192.168.50.9",
                ByteArray(32),
                Duration.ofSeconds(31),
                Duration.ofSeconds(3),
            )
        }
    }

    @Test
    fun rejectsAllIncompleteOrMismatchedDirectEvidence() {
        val current = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val exact = TrustedDirectProbeFactory.fromPinnedTls(evidence(current))
        assertEquals(
            DirectReadinessStatus.DIRECT_READY,
            DirectReadinessAdapter.assess(current, exact).status,
        )

        val mutations =
            listOf(
                evidence(current).copy(path = DirectPath.TAILSCALE),
                evidence(current).copy(connect = DirectEndpoint("192.168.50.7", 8443)),
                evidence(current).copy(listenInterface = "192.168.50.7"),
                evidence(current).copy(epoch = 6),
                evidence(current).copy(peerSpki = ByteArray(32) { 0x12 }),
                evidence(current).copy(transport = DirectTransportKind.DIAGNOSTIC_USB),
            )
        mutations.forEach { mutation ->
            val result =
                DirectReadinessAdapter.assess(
                    current,
                    TrustedDirectProbeFactory.fromPinnedTls(mutation),
                    UsbDiagnosticEvidence(DiagnosticTransportKind.DIAGNOSTIC_USB_RELAY, true),
                )
            assertEquals(DirectReadinessStatus.DIRECT_NETWORK_BLOCKED, result.status)
            assertTrue(requireNotNull(result.diagnosticUsb).succeeded)
        }
        assertEquals(
            DirectReadinessStatus.DIRECT_NETWORK_BLOCKED,
            DirectReadinessAdapter.assess(current, DirectProbe.Unreachable).status,
        )
    }

    @Test
    fun usbCannotSatisfyDirect() {
        val current = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val result =
            DirectReadinessAdapter.assess(
                current,
                DirectProbe.Unreachable,
                UsbDiagnosticEvidence(DiagnosticTransportKind.DIAGNOSTIC_USB_RELAY, true),
            )

        assertEquals(DirectReadinessStatus.DIRECT_NETWORK_BLOCKED, result.status)
        assertTrue(requireNotNull(result.diagnosticUsb).succeeded)
    }

    @Test
    fun rotationRejectsStaleDirectEvidence() {
        val original = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val stale = TrustedDirectProbeFactory.fromPinnedTls(evidence(original))
        val next = profile(8, DirectPath.LAN, "192.168.50.10", "192.168.50.9", 0x22)
        val rotation = DirectProfileRotation(original)
        rotation.prepare(next)
        rotation.activate()

        assertSame(next, rotation.active)
        assertEquals(
            DirectReadinessStatus.DIRECT_NETWORK_BLOCKED,
            DirectReadinessAdapter.assess(rotation.active, stale).status,
        )
    }

    private fun profile(
        epoch: Long,
        path: DirectPath,
        host: String,
        listenInterface: String,
        pin: Int,
    ): DirectProfile =
        DirectProfile.create(
            epoch,
            path,
            DirectEndpoint(host, 8443),
            listenInterface,
            ByteArray(32) { pin.toByte() },
            Duration.ofSeconds(2),
            Duration.ofSeconds(3),
        )

    private fun evidence(profile: DirectProfile): DirectEvidenceInput =
        DirectEvidenceInput(
            profile.path,
            profile.connect,
            profile.listenInterface,
            profile.epoch,
            profile.peerSpki(),
            DirectTransportKind.DIRECT_PINNED_TLS,
        )

    private fun assertFailure(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        }
        throw AssertionError("expected IllegalArgumentException")
    }
}
