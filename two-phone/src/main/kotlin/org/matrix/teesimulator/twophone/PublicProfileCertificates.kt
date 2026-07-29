package org.matrix.teesimulator.twophone

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec

internal data class ValidatedPublicCertificate(
    val certificate: X509Certificate,
    val der: ByteArray,
    val pin: PublicProfilePin,
)

internal fun validatePublicCertificate(field: Int, source: ByteArray): ValidatedPublicCertificate {
    try {
        if (source.isEmpty()) throw PublicProfileException.InvalidCertificate(field)
        val der = source.copyOf()
        val input = ByteArrayInputStream(der)
        val certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(input) as? X509Certificate
                ?: throw PublicProfileException.InvalidCertificate(field)
        if (input.available() != 0 || !MessageDigest.isEqual(der, certificate.encoded)) {
            throw PublicProfileException.InvalidCertificate(field)
        }
        val spki =
            certificate.publicKey.encoded?.copyOf()
                ?: throw PublicProfileException.InvalidCertificate(field)
        val reparsed =
            KeyFactory.getInstance(certificate.publicKey.algorithm)
                .generatePublic(X509EncodedKeySpec(spki))
                .encoded
        if (!MessageDigest.isEqual(spki, reparsed)) {
            throw PublicProfileException.InvalidCertificate(field)
        }
        return ValidatedPublicCertificate(
            certificate,
            der,
            PublicProfilePin.fromDigest(MessageDigest.getInstance("SHA-256").digest(spki)),
        )
    } catch (failure: PublicProfileException.InvalidCertificate) {
        throw failure
    } catch (failure: Exception) {
        throw PublicProfileException.InvalidCertificate(field, failure)
    }
}

internal fun validatePublicChain(
    field: Int,
    source: List<ByteArray>,
    expectedLeaf: ByteArray? = null,
): List<ByteArray> {
    if (source.size !in 2..PublicProfileBinary.MAX_CERTIFICATES) {
        throw PublicProfileException.InvalidFieldLength(field)
    }
    val certificates = source.map { validatePublicCertificate(field, it) }
    if (expectedLeaf != null && !MessageDigest.isEqual(certificates.first().der, expectedLeaf)) {
        throw PublicProfileException.CertificateMismatch(field)
    }
    try {
        certificates.zipWithNext().forEach { (certificate, issuer) ->
            if (
                certificate.certificate.issuerX500Principal !=
                    issuer.certificate.subjectX500Principal
            ) {
                throw PublicProfileException.CertificateMismatch(field)
            }
            certificate.certificate.verify(issuer.certificate.publicKey)
        }
        val root = certificates.last().certificate
        if (root.basicConstraints < 0 || root.issuerX500Principal != root.subjectX500Principal) {
            throw PublicProfileException.CertificateMismatch(field)
        }
        root.verify(root.publicKey)
    } catch (failure: PublicProfileException.CertificateMismatch) {
        throw failure
    } catch (_: Exception) {
        throw PublicProfileException.CertificateMismatch(field)
    }
    return certificates.map(ValidatedPublicCertificate::der)
}

internal fun requirePin(field: Int, expected: PublicProfilePin, certificateDer: ByteArray) {
    val actual = validatePublicCertificate(field, certificateDer).pin
    if (actual != expected) throw PublicProfileException.PinMismatch(field)
}
