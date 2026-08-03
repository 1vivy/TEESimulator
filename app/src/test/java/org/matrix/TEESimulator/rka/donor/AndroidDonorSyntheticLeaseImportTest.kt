package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDonorSyntheticLeaseImportTest {
    @Test
    fun importsCallerOwnedP256AsSoleAttestKeyAndDeletesTheTemporaryBlob() {
        val fixture = DonorFixture()
        val leaseKey = ecKey()
        val device = FakeDonorKeyMintDevice(fixture).apply { syntheticLeaseKey = leaseKey }
        val privatePkcs8 = DonorSecretBytes.of(leaseKey.private.encoded, 4_096)
        val now = Instant.now()
        val parameters =
            DonorSyntheticLeaseParameters.exact(
                fixture.challenge,
                fixture.aaid,
                now.minusSeconds(300).toEpochMilli(),
                now.plusSeconds(7 * 24 * 60 * 60).toEpochMilli(),
            )

        val creation =
            privatePkcs8.use { secret ->
                device.importSyntheticLease(
                    parameters,
                    secret,
                    DonorAttestationKey(
                        ByteArray(32) { 0x5a },
                        fixture.rkpCertificate.subjectX500Principal.encoded,
                    ),
                )
            }
        val leaseCertificate = parse(creation.certificateChain.single())
        creation.withKeyBlob { device.delete(it) }
        creation.close()

        assertEquals(DonorSyntheticLeaseCharacteristics.exact(), creation.characteristics)
        assertArrayEquals(leaseKey.public.encoded, leaseCertificate.publicKey.encoded)
        leaseCertificate.verify(fixture.rkpCertificate.publicKey)
        assertEquals(
            fixture.rkpCertificate.subjectX500Principal,
            leaseCertificate.issuerX500Principal,
        )
        assertEquals(1, device.importSyntheticLeaseCalls)
        assertEquals(1, device.deleteCalls)
        assertTrue(creation.isDestroyedForTest())
        assertThrows(IllegalStateException::class.java) { privatePkcs8.copyBytes() }
    }

    private fun parse(encoded: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(encoded))
            as X509Certificate
}
