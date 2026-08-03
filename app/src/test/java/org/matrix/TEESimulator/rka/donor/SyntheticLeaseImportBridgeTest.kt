package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.time.Instant
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BridgeCodec
import org.matrix.TEESimulator.rka.bridge.BridgeExchangeRole
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.DonorProvisioningRuntime
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.bridge.RequestId
import org.matrix.TEESimulator.rka.bridge.SecretBytes
import org.matrix.TEESimulator.rka.journal.RkpJournalState

class SyntheticLeaseImportBridgeTest {
    @Test
    fun localProbeRoundTripsOneBoundedSecretAndRedactsEveryDescription() {
        val fixture = DonorFixture()
        val pkcs8 = ecKey().private.encoded
        val expectedSpki = ecKey().public.encoded
        val secret = SecretBytes.of(pkcs8, BridgeLimits.MAX_SYNTHETIC_LEASE_PKCS8_BYTES)
        val request =
            BridgeMessage.SyntheticLeaseProbeRequest(
                RequestId(71),
                Hash32.of(fixture.rkpHandle.copyBytes()),
                secret,
                PublicBytes.of(expectedSpki, BridgeLimits.MAX_CERTIFICATE_BYTES),
                PublicBytes.of(fixture.challenge, 64),
                PublicBytes.of(fixture.aaid, 131_072),
                1_700_000_000_000L,
                1_700_604_800_000L,
                fixture.chain.map { PublicBytes.of(it, BridgeLimits.MAX_CERTIFICATE_BYTES) },
            )

        val encoded = BridgeCodec.encode(request, BridgeExchangeRole.DONOR_REQUEST)
        val decoded =
            BridgeCodec.decode(ByteArrayInputStream(encoded), BridgeExchangeRole.DONOR_REQUEST)

        assertTrue(decoded is BridgeResult.Success)
        val decodedRequest = (decoded as BridgeResult.Success).value
        assertTrue(decodedRequest is BridgeMessage.SyntheticLeaseProbeRequest)
        decodedRequest as BridgeMessage.SyntheticLeaseProbeRequest
        assertArrayEquals(pkcs8, decodedRequest.privateKeyPkcs8.copyBytes())
        assertFalse(request.toString().contains(pkcs8.joinToString()))
        assertFalse(decodedRequest.toString().contains(pkcs8.joinToString()))
        assertTrue(request.toString().contains("privateKey=redacted"))

        request.close()
        decodedRequest.close()
        assertThrows(IllegalStateException::class.java) { secret.copyBytes() }
        assertThrows(IllegalStateException::class.java) {
            decodedRequest.privateKeyPkcs8.copyBytes()
        }
    }

    @Test
    fun probeResponseContainsOnlyPublicCertificateMaterial() {
        val fixture = DonorFixture()
        val response =
            BridgeMessage.SyntheticLeaseProbeResponse(
                RequestId(72),
                fixture.chain.map { PublicBytes.of(it, BridgeLimits.MAX_CERTIFICATE_BYTES) },
            )

        val encoded = BridgeCodec.encode(response, BridgeExchangeRole.DONOR_RESPONSE)
        val decoded =
            BridgeCodec.decode(ByteArrayInputStream(encoded), BridgeExchangeRole.DONOR_RESPONSE)

        assertTrue(decoded is BridgeResult.Success)
        val decodedResponse = (decoded as BridgeResult.Success).value
        assertTrue(decodedResponse is BridgeMessage.SyntheticLeaseProbeResponse)
        decodedResponse as BridgeMessage.SyntheticLeaseProbeResponse
        assertEquals(fixture.chain.size, decodedResponse.certificateChain().size)
        assertFalse(encoded.contains(ByteArray(32) { 0x5a }))
        assertTrue(decodedResponse.toString().contains("certificateCount=${fixture.chain.size}"))

        response.close()
        decodedResponse.close()
    }

    @Test
    fun authenticatedRuntimeImportsValidatesDeletesAndReturnsCanonicalPublicChain() {
        val fixture = DonorFixture()
        val leaseKey = ecKey()
        val now = Instant.now()
        val device = FakeDonorKeyMintDevice(fixture).apply { syntheticLeaseKey = leaseKey }
        val request =
            BridgeMessage.SyntheticLeaseProbeRequest(
                RequestId(73),
                Hash32.of(fixture.rkpHandle.copyBytes()),
                SecretBytes.of(
                    leaseKey.private.encoded,
                    BridgeLimits.MAX_SYNTHETIC_LEASE_PKCS8_BYTES,
                ),
                PublicBytes.of(leaseKey.public.encoded, BridgeLimits.MAX_CERTIFICATE_BYTES),
                PublicBytes.of(fixture.challenge, 64),
                PublicBytes.of(fixture.aaid, 131_072),
                now.minusSeconds(300).toEpochMilli(),
                now.plusSeconds(7 * 24 * 60 * 60).toEpochMilli(),
                fixture.chain.map { PublicBytes.of(it, BridgeLimits.MAX_CERTIFICATE_BYTES) },
            )

        val response =
            DonorProvisioningRuntime.probeSyntheticLeaseForTest(request, device, fixture.journal)

        assertTrue(response is BridgeMessage.SyntheticLeaseProbeResponse)
        response as BridgeMessage.SyntheticLeaseProbeResponse
        assertEquals(fixture.chain.size + 1, response.certificateChain().size)
        assertEquals(1, device.importSyntheticLeaseCalls)
        assertEquals(1, device.deleteCalls)
        assertEquals(RkpJournalState.DELETE, fixture.journal.recover()?.state)

        response.close()
        request.close()
    }

    private fun ByteArray.contains(candidate: ByteArray): Boolean =
        indices.any { start ->
            start + candidate.size <= size &&
                candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
        }
}
