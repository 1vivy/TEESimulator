package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.SpkiPinException

class SpkiPinTest {
    private val encodedKey = "abc".encodeToByteArray()
    private val canonical = "sha256/ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="

    @Test
    fun knownDigestVectorAndCanonicalRoundTrip() {
        val pin = SpkiPin.from(TestPublicKey(encodedKey))

        assertEquals(canonical, pin.toString())
        assertEquals(canonical, SpkiPin.parse(canonical).toString())
        assertEquals(51, pin.toString().length)
    }

    @Test
    fun createsFromCertificatePublicKey() {
        val identity =
            CallerIdentityCanonicalizer()
                .canonicalize(
                    listOf(CallerPackageIdentity("org.example.pin", 1, listOf(byteArrayOf(1))))
                )
        val material =
            SyntheticAndroidKeyAttestation.material(
                testBytes(32, 4),
                identity.attestationApplicationIdDer,
            )
        val certificate =
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(material.certificateChain.first()))
                as java.security.cert.X509Certificate

        assertEquals(
            SpkiPin.from(certificate.publicKey).toString(),
            SpkiPin.from(certificate).toString(),
        )
    }

    @Test
    fun rejectsEveryNonCanonicalPinCategoryWithoutEchoingInput() {
        val body = canonical.removePrefix("sha256/")
        val malformed =
            listOf(
                " $canonical",
                "$canonical\n",
                canonical.replace("+", "-"),
                canonical.dropLast(1),
                "$canonical=",
                canonical.replaceFirst("sha256/", "SHA256/"),
                canonical.replaceFirst("sha256/", "sha512/"),
                "sha256/${Base64.getEncoder().encodeToString(ByteArray(31))}",
                "sha256/${body.replaceRange(3, 4, "!")}",
                "sha256/${body.dropLast(2)}1=",
            )

        malformed.forEach { value ->
            val failure = assertFailsWith<SpkiPinException.InvalidFormat> { SpkiPin.parse(value) }
            assertEquals("invalid SPKI pin", failure.message)
            assertFalse(failure.message.orEmpty().contains(value))
        }
    }

    @Test
    fun matchingUsesEncodedSpkiAndDigestBytesAreDefensive() {
        val pin = SpkiPin.parse(canonical)
        val digest = pin.digest
        digest.fill(0)

        assertTrue(pin.matches(TestPublicKey(encodedKey)))
        assertFalse(pin.matches(TestPublicKey("abd".encodeToByteArray())))
        assertTrue(pin.digest.any { it.toInt() != 0 })
    }

    private class TestPublicKey(private val bytes: ByteArray) : PublicKey {
        override fun getAlgorithm() = "test"

        override fun getFormat() = "X.509"

        override fun getEncoded() = bytes.copyOf()
    }
}
