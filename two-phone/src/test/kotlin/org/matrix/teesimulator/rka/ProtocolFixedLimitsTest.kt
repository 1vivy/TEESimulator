package org.matrix.teesimulator.rka

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Test

class ProtocolFixedLimitsTest {
    @Test
    fun globalLimitsAcceptTheirExactMaximums() {
        // Given: values at every global fixed boundary.
        val nonce =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(ByteArray(RkaLimits.FIXTURE_NONCE_BYTES))
        val donor = DeviceSerial.parse(DeviceRole.DONOR, "donor:1")
        val candidate = DeviceSerial.parse(DeviceRole.CANDIDATE, "candidate:1")

        // When: each value is parsed by the reference boundary.
        RkaLimits.requireRoleConfig(ByteArray(RkaLimits.ROLE_CONFIG_BYTES))
        RkaLimits.requireProfile(ByteArray(RkaLimits.PROFILE_BYTES))
        RkaLimits.requireProfileId("p".repeat(RkaLimits.PROFILE_ID_BYTES))
        RkaLimits.requireFixtureNonce(nonce)
        RkaLimits.requireDistinctSerials(donor, candidate)
        RkaLimits.requireEndpointCount(RkaLimits.DIRECT_ENDPOINTS)
        RkaLimits.requireRequestCount(RkaLimits.REQUESTS_PER_SESSION)
        RkaLimits.requireOperationInput(RkaLimits.OPERATION_INPUT_BYTES)
        RkaLimits.requireDeadline(1_000u, 121_000u)

        // Then: the protocol constants retain the approved timeout and identity widths.
        assertEquals(32, RkaLimits.SESSION_BINDING_BYTES)
        assertEquals(16, RkaLimits.REQUEST_ID_BYTES)
        assertEquals(32, RkaLimits.PHYSICAL_CHALLENGE_BYTES)
        assertEquals(5, RkaLimits.CONNECT_TIMEOUT_SECONDS)
        assertEquals(5, RkaLimits.READ_TIMEOUT_SECONDS)
        assertEquals(10, RkaLimits.WRITE_TIMEOUT_SECONDS)
        assertEquals(30, RkaLimits.FRAME_TIMEOUT_SECONDS)
    }

    @Test
    fun globalLimitsRejectOnePastMaximumOrInvalidIdentity() {
        // Given: every non-payload global bound exceeded by one or invalid by shape.
        val actions =
            listOf<() -> Unit>(
                { RkaLimits.requireRoleConfig(ByteArray(RkaLimits.ROLE_CONFIG_BYTES + 1)) },
                { RkaLimits.requireProfile(ByteArray(RkaLimits.PROFILE_BYTES + 1)) },
                { RkaLimits.requireProfileId("p".repeat(RkaLimits.PROFILE_ID_BYTES + 1)) },
                { RkaLimits.requireProfileId("invalid/profile") },
                { RkaLimits.requireFixtureNonce("A".repeat(21)) },
                { DeviceSerial.parse(DeviceRole.DONOR, "invalid serial") },
                {
                    RkaLimits.requireDistinctSerials(
                        DeviceSerial.parse(DeviceRole.DONOR, "same"),
                        DeviceSerial.parse(DeviceRole.CANDIDATE, "same"),
                    )
                },
                { RkaLimits.requireEndpointCount(RkaLimits.DIRECT_ENDPOINTS + 1) },
                { RkaLimits.requireRequestCount(RkaLimits.REQUESTS_PER_SESSION + 1) },
                { RkaLimits.requireOperationInput(RkaLimits.OPERATION_INPUT_BYTES + 1) },
                { RkaLimits.requireDeadline(1_000u, 121_001u) },
            )

        // When: each invalid value crosses the reference boundary.
        val rejected = actions.count { action -> runCatching(action).isFailure }

        // Then: every invalid value is rejected.
        assertEquals(actions.size, rejected)
    }

    @Test
    fun frameFieldWidthsRejectEveryInvalidLength() {
        // Given: one canonical frame and each fixed-width field shortened by one byte.
        val frame = GoldenVectorFixtures.frame()
        val invalid =
            listOf(
                frame.copy(sessionId = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(requestId = ByteArray(RkaLimits.REQUEST_ID_BYTES - 1)),
                frame.copy(clientNonce = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(serverNonce = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(candidateTlsPin = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(peerTlsPin = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(donorFingerprint = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(callerIdentityHash = ByteArray(RkaLimits.SESSION_BINDING_BYTES - 1)),
                frame.copy(payload = ByteArray(RkaLimits.FRAME_BYTES)),
            )

        // When: each invalid frame crosses the codec boundary.
        val rejected =
            invalid.count { value -> runCatching { RkaReferenceCodec.encode(value) }.isFailure }

        // Then: every fixed-width or frame-size violation is rejected.
        assertEquals(invalid.size, rejected)
    }
}
