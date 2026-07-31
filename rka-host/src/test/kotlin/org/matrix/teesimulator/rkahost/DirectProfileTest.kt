package org.matrix.teesimulator.rkahost

import java.time.Duration
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        assertEquals(7, lan.epoch)
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
        assertFailure { DirectEndpoint("donor.tailnet.ts.net", 0) }
        assertFailure { DirectEndpoint("192.168.050.8", 8443) }
        assertFailure {
            DirectProfile.create(
                1,
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
                1,
                DirectPath.LAN,
                DirectEndpoint("192.168.50.8", 8443),
                "192.168.50.09",
                ByteArray(32),
                Duration.ofSeconds(31),
                Duration.ofSeconds(3),
            )
        }
    }

    @Test
    fun staleEpochPinAddressOrEndpointCannotBePromoted() {
        val current = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val exact =
            DirectProbe.Reachable(7, current.connect, current.listenAddress, current.peerSpki())
        assertEquals(
            DirectReadinessStatus.DIRECT_READY,
            DirectReadinessAdapter.assess(current, exact).status,
        )
        val mutations =
            listOf(
                DirectProbe.Reachable(
                    6,
                    current.connect,
                    current.listenAddress,
                    current.peerSpki(),
                ),
                DirectProbe.Reachable(
                    7,
                    DirectEndpoint("192.168.50.7", 8443),
                    current.listenAddress,
                    current.peerSpki(),
                ),
                DirectProbe.Reachable(7, current.connect, "192.168.50.7", current.peerSpki()),
                DirectProbe.Reachable(
                    7,
                    current.connect,
                    current.listenAddress,
                    ByteArray(32) { 0x12 },
                ),
            )
        mutations.forEach {
            assertEquals(
                DirectReadinessStatus.DIRECT_NETWORK_BLOCKED,
                DirectReadinessAdapter.assess(current, it).status,
            )
        }
    }

    @Test
    fun usbCannotSatisfyDirect() {
        val profile = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val result =
            DirectReadinessAdapter.assess(
                profile,
                DirectProbe.Unreachable,
                UsbDiagnosticEvidence(succeeded = true),
            )

        assertEquals(DirectReadinessStatus.DIRECT_NETWORK_BLOCKED, result.status)
        assertTrue(requireNotNull(result.diagnosticUsb).succeeded)
    }

    @Test
    fun rotationAndSelectionAreDeterministicWithoutCredentialStateOrFallback() {
        val original = profile(7, DirectPath.LAN, "192.168.50.8", "192.168.50.9", 0x11)
        val next = profile(8, DirectPath.LAN, "192.168.50.10", "192.168.50.9", 0x22)
        val rotation = DirectProfileRotation(original)
        rotation.prepare(next)
        rotation.activate()

        assertSame(next, rotation.active)
        assertSame(next, DirectProfileSelector.select(listOf(original, next), DirectPath.LAN))
        assertEquals(
            DirectReadinessStatus.DIRECT_NETWORK_BLOCKED,
            DirectReadinessAdapter.assess(
                    rotation.active,
                    DirectProbe.Reachable(
                        original.epoch,
                        original.connect,
                        original.listenAddress,
                        original.peerSpki(),
                    ),
                )
                .status,
        )
        assertFalse(
            DirectProfile::class.java.declaredFields.any {
                it.name.contains("credential", true) ||
                    it.name.contains("auth", true) ||
                    it.name.contains("discovery", true) ||
                    it.name.contains("fallback", true)
            }
        )
    }

    private fun profile(
        epoch: Long,
        path: DirectPath,
        host: String,
        listen: String,
        pin: Int,
    ): DirectProfile =
        DirectProfile.create(
            epoch,
            path,
            DirectEndpoint(host, 8443),
            listen,
            ByteArray(32) { pin.toByte() },
            Duration.ofSeconds(2),
            Duration.ofSeconds(3),
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
