package org.matrix.TEESimulator.rka.donor

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DonorKeyMintSubjectTest {
    @Test
    fun firstCertificateDerSubjectIsAcceptedAndIssuerIsRejected() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture)
        val backend = DonorKeyMintBackend(device, fixture.journal)

        // When
        backend.generate(fixture.request()).success()

        // Then
        val key = requireNotNull(device.lastAttestationKey)
        assertFalse(
            fixture.rkpCertificate.subjectX500Principal ==
                fixture.rkpCertificate.issuerX500Principal
        )
        assertArrayEquals(
            fixture.rkpCertificate.subjectX500Principal.encoded,
            key.issuerSubjectName,
        )
        assertFalse(
            fixture.rkpCertificate.issuerX500Principal.encoded.contentEquals(key.issuerSubjectName)
        )
        assertEquals(0, key.attestKeyParams.size)
    }
}
