package org.matrix.teesimulator.physicalharness

import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class DonorTargetTrustStoreTest {
    @Test
    fun containsOnlyConfiguredCanonicalAnchorsUnderStableNames() {
        val fixture = DonorProfileFixture()
        val configured = listOf(fixture.targetRoot.certificate, fixture.otherRoot.certificate)
        val profile = fixture.profile(targetTrustAnchorDer = configured.map { it.encoded })

        val trustStore = DonorTargetTrustStore.create(profile)

        assertEquals(
            listOf("target-anchor-0000", "target-anchor-0001"),
            trustStore.aliases().toList().sorted(),
        )
        configured.forEachIndexed { index, certificate ->
            val stored =
                trustStore.getCertificate("target-anchor-%04d".format(index)) as X509Certificate
            assertContentEquals(certificate.encoded, stored.encoded)
        }
        assertEquals(2, trustStore.size())
    }
}
