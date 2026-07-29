package org.matrix.teesimulator.physicalharness

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.matrix.teesimulator.twophone.WireCallerIdentity

class CallerPackageIdentity(
    val packageName: String,
    val longVersionCode: Long,
    signingCertificateHistory: Collection<ByteArray>,
) {
    private val signingCertificateHistoryBytes = signingCertificateHistory.map(ByteArray::copyOf)

    val signingCertificateHistory: List<ByteArray>
        get() = signingCertificateHistoryBytes.map(ByteArray::copyOf)

    init {
        val packageNameBytes = packageName.toByteArray(StandardCharsets.UTF_8)
        require(packageName.isNotBlank()) { "Package name must not be blank" }
        require(packageNameBytes.size <= MAX_PACKAGE_NAME_UTF8_BYTES) {
            "Package name exceeds $MAX_PACKAGE_NAME_UTF8_BYTES UTF-8 bytes"
        }
        require(longVersionCode >= 0) { "Version code must be nonnegative" }
        require(signingCertificateHistoryBytes.isNotEmpty()) {
            "Signing certificate history must not be empty"
        }
        signingCertificateHistoryBytes.forEach { certificate ->
            require(certificate.isNotEmpty()) { "Signing certificate must not be empty" }
            require(certificate.size <= MAX_SIGNING_CERTIFICATE_BYTES) {
                "Signing certificate exceeds $MAX_SIGNING_CERTIFICATE_BYTES bytes"
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CallerPackageIdentity) return false
        return packageName == other.packageName &&
            longVersionCode == other.longVersionCode &&
            signingCertificateHistoryBytes.contentEquals(other.signingCertificateHistoryBytes)
    }

    override fun hashCode(): Int {
        var result = packageName.hashCode()
        result = 31 * result + longVersionCode.hashCode()
        result = 31 * result + signingCertificateHistoryBytes.contentHashCode()
        return result
    }

    private fun List<ByteArray>.contentEquals(other: List<ByteArray>): Boolean =
        size == other.size && indices.all { this[it].contentEquals(other[it]) }

    private fun List<ByteArray>.contentHashCode(): Int =
        fold(1) { result, bytes -> 31 * result + bytes.contentHashCode() }

    companion object {
        const val MAX_PACKAGE_NAME_UTF8_BYTES = 255
        const val MAX_SIGNING_CERTIFICATE_BYTES = 1024 * 1024
    }
}

class CanonicalCallerIdentity(
    attestationApplicationIdDer: ByteArray,
    val wireIdentity: WireCallerIdentity,
) {
    private val attestationApplicationIdDerBytes = attestationApplicationIdDer.copyOf()

    val attestationApplicationIdDer: ByteArray
        get() = attestationApplicationIdDerBytes.copyOf()

    init {
        require(attestationApplicationIdDerBytes.isNotEmpty()) {
            "Attestation application ID DER must not be empty"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanonicalCallerIdentity) return false
        return wireIdentity == other.wireIdentity &&
            attestationApplicationIdDerBytes.contentEquals(other.attestationApplicationIdDerBytes)
    }

    override fun hashCode(): Int =
        31 * wireIdentity.hashCode() + attestationApplicationIdDerBytes.contentHashCode()
}

class CallerIdentityCanonicalizer {
    fun canonicalize(packages: Collection<CallerPackageIdentity>): CanonicalCallerIdentity {
        require(packages.isNotEmpty()) { "Caller packages must not be empty" }

        val packageSet =
            DERSet(
                packages
                    .map { packageIdentity ->
                        DERSequence(
                            arrayOf(
                                DEROctetString(
                                    packageIdentity.packageName.toByteArray(StandardCharsets.UTF_8)
                                ),
                                ASN1Integer(packageIdentity.longVersionCode),
                            )
                        )
                    }
                    .toTypedArray()
            )
        val uniqueSignerDigests =
            packages
                .asSequence()
                .flatMap { it.signingCertificateHistory.asSequence() }
                .map(::sha256)
                .distinctBy { it.lowercaseHex() }
                .toList()
        val signerDigestSet = DERSet(uniqueSignerDigests.map(::DEROctetString).toTypedArray())
        val attestationApplicationIdDer = DERSequence(arrayOf(packageSet, signerDigestSet)).encoded

        return CanonicalCallerIdentity(
            attestationApplicationIdDer,
            WireCallerIdentity(
                signingCertificateDigest = sha256(signerDigestSet.encoded).lowercaseHex(),
                attestationApplicationIdDigest = sha256(attestationApplicationIdDer).lowercaseHex(),
            ),
        )
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance(SHA_256).digest(bytes)

    private fun ByteArray.lowercaseHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val SHA_256 = "SHA-256"
    }
}
