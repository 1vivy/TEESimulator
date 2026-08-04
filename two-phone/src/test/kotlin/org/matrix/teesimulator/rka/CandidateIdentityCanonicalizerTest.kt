package org.matrix.teesimulator.rka

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import org.junit.Assert.assertFalse
import org.junit.Test

class CandidateIdentityCanonicalizerTest {
    @Test
    fun candidateBIdentityHashDiffersFromCandidateA() {
        // Given: candidate A's co-current signing set and candidate B's independent signer.
        val candidateAHash =
            canonicalIdentityHash(
                "/candidate-identity/current-a.der.hex",
                "/candidate-identity/current-b.der.hex",
            )
        val candidateBHash =
            canonicalIdentityHash("/candidate-identity/candidate-b/current.der.hex")

        // When: both signing identities are canonicalized under the frozen fixture domain.
        val identitiesMatch = candidateAHash.contentEquals(candidateBHash)

        // Then: the second fixture represents a genuinely different candidate identity.
        assertFalse(identitiesMatch)
    }

    private fun canonicalIdentityHash(vararg signerResources: String): ByteArray {
        val canonicalSigners =
            signerResources
                .map { path ->
                    val der = resource(path).decodeHex()
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(der.inputStream())
                        .encoded
                }
                .sortedBy { signer -> signer.toHex() }
        return MessageDigest.getInstance("SHA-256").apply {
                update("candidate-identity-vector-v1\u0000".encodeToByteArray())
                canonicalSigners.forEach { signer ->
                    update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(signer.size).array())
                    update(signer)
                }
            }
            .digest()
    }

    private fun resource(path: String): String =
        requireNotNull(javaClass.getResource(path)) { "missing test resource: $path" }.readText()

    private fun String.decodeHex(): ByteArray =
        filterNot(Char::isWhitespace).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
