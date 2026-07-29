package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import org.matrix.teesimulator.twophone.SpkiPin

sealed class DonorProfileException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class InvalidProfileId : DonorProfileException("invalid donor profile identifier")

    class InvalidBindAddress : DonorProfileException("invalid donor bind address")

    class InvalidPort : DonorProfileException("invalid donor port")

    class InvalidCertificate(cause: Throwable? = null) :
        DonorProfileException("invalid donor profile certificate", cause)

    class InvalidTrustAnchors : DonorProfileException("invalid donor target trust anchors")

    class TargetPinMismatch : DonorProfileException("donor target identity pin mismatch")
}

class DonorProfile
private constructor(
    val profileId: String,
    bindAddress: InetAddress,
    val port: Int,
    val expectedDonorPin: SpkiPin,
    val expectedTargetPin: SpkiPin,
    targetIdentityCertificateDer: ByteArray,
    targetTrustAnchorDer: List<ByteArray>,
    internal val targetTrustAnchorCertificates: List<X509Certificate>,
) {
    private val bindAddressBytes = bindAddress.address.copyOf()
    private val bindScopeId = (bindAddress as? Inet6Address)?.scopeId ?: 0
    private val stableTargetIdentityCertificateDer = targetIdentityCertificateDer.copyOf()
    private val stableTargetTrustAnchorDer = targetTrustAnchorDer.map(ByteArray::copyOf)
    private val fingerprintBytes = calculateFingerprint()

    val bindAddress: InetAddress
        get() =
            if (bindAddressBytes.size == IPV6_BYTES) {
                Inet6Address.getByAddress(null, bindAddressBytes.copyOf(), bindScopeId)
            } else {
                InetAddress.getByAddress(bindAddressBytes.copyOf())
            }

    val targetIdentityCertificateDer: ByteArray
        get() = stableTargetIdentityCertificateDer.copyOf()

    val targetTrustAnchorDer: List<ByteArray>
        get() = stableTargetTrustAnchorDer.map(ByteArray::copyOf)

    val fingerprint: ByteArray
        get() = fingerprintBytes.copyOf()

    private fun calculateFingerprint(): ByteArray {
        val digest = MessageDigest.getInstance(SHA_256)
        digest.updateField(FINGERPRINT_DOMAIN)
        digest.updateField(profileId.toByteArray(StandardCharsets.US_ASCII))
        digest.updateField(bindAddressBytes)
        digest.updateField(intBytes(bindScopeId))
        digest.updateField(intBytes(port))
        digest.updateField(expectedDonorPin.toString().toByteArray(StandardCharsets.US_ASCII))
        digest.updateField(expectedTargetPin.toString().toByteArray(StandardCharsets.US_ASCII))
        digest.updateField(stableTargetIdentityCertificateDer)
        digest.updateField(intBytes(stableTargetTrustAnchorDer.size))
        stableTargetTrustAnchorDer.forEach { digest.updateField(it) }
        return digest.digest()
    }

    companion object {
        private val VALID_PROFILE_ID = Regex("[A-Za-z0-9._-]{1,64}")
        private const val IPV4_BYTES = 4
        private const val IPV6_BYTES = 16
        private const val SHA_256 = "SHA-256"
        private val FINGERPRINT_DOMAIN =
            "TEESimulator\u0000donor-profile\u0000v1".toByteArray(StandardCharsets.US_ASCII)

        fun create(
            profileId: String,
            bindAddress: InetAddress,
            port: Int,
            expectedDonorPin: SpkiPin,
            expectedTargetPin: SpkiPin,
            targetIdentityCertificateDer: ByteArray,
            targetTrustAnchorDer: List<ByteArray>,
            now: Instant,
        ): DonorProfile {
            requireValidProfileId(profileId)
            validateBindAddress(bindAddress)
            if (port !in 1..65_535) throw DonorProfileException.InvalidPort()
            val identity = parseCertificate(targetIdentityCertificateDer, now)
            if (!expectedTargetPin.matches(identity.certificate)) {
                throw DonorProfileException.TargetPinMismatch()
            }
            if (targetTrustAnchorDer.isEmpty()) {
                throw DonorProfileException.InvalidTrustAnchors()
            }
            val anchors = targetTrustAnchorDer.map { parseCertificate(it, now) }
            return DonorProfile(
                profileId,
                bindAddress,
                port,
                expectedDonorPin,
                expectedTargetPin,
                identity.der,
                anchors.map(ParsedCertificate::der),
                anchors.map(ParsedCertificate::certificate),
            )
        }

        fun requireValidProfileId(profileId: String): String {
            if (!VALID_PROFILE_ID.matches(profileId)) {
                throw DonorProfileException.InvalidProfileId()
            }
            return profileId
        }

        private fun validateBindAddress(bindAddress: InetAddress) {
            val size = bindAddress.address.size
            if ((size != IPV4_BYTES && size != IPV6_BYTES) || bindAddress.isMulticastAddress) {
                throw DonorProfileException.InvalidBindAddress()
            }
        }

        private fun parseCertificate(der: ByteArray, now: Instant): ParsedCertificate =
            try {
                if (der.isEmpty()) throw DonorProfileException.InvalidCertificate()
                val stableDer = der.copyOf()
                val input = ByteArrayInputStream(stableDer)
                val certificate =
                    CertificateFactory.getInstance("X.509").generateCertificate(input)
                        as? X509Certificate ?: throw DonorProfileException.InvalidCertificate()
                if (
                    input.available() != 0 || !MessageDigest.isEqual(stableDer, certificate.encoded)
                ) {
                    throw DonorProfileException.InvalidCertificate()
                }
                certificate.checkValidity(Date.from(now))
                ParsedCertificate(certificate, stableDer)
            } catch (failure: DonorProfileException.InvalidCertificate) {
                throw failure
            } catch (failure: Exception) {
                throw DonorProfileException.InvalidCertificate(failure)
            }

        private fun MessageDigest.updateField(value: ByteArray) {
            update(intBytes(value.size))
            update(value)
        }

        private fun intBytes(value: Int): ByteArray =
            ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value).array()

        private data class ParsedCertificate(val certificate: X509Certificate, val der: ByteArray)
    }
}
