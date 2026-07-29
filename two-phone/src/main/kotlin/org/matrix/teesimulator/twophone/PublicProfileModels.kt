package org.matrix.teesimulator.twophone

import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

enum class PublicProfileVersion {
    V1
}

class PublicProfilePin private constructor(digest: ByteArray) {
    private val digestBytes = digest.copyOf()
    private val canonical = "sha256/" + Base64.getEncoder().encodeToString(digestBytes)

    val digest: ByteArray
        get() = digestBytes.copyOf()

    override fun toString(): String = canonical

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is PublicProfilePin && MessageDigest.isEqual(digestBytes, other.digestBytes))

    override fun hashCode(): Int = digestBytes.contentHashCode()

    companion object {
        fun fromCertificate(certificateDer: ByteArray): PublicProfilePin =
            validatePublicCertificate(PublicProfileField.TARGET_CERTIFICATE, certificateDer).pin

        internal fun fromDigest(digest: ByteArray): PublicProfilePin {
            if (digest.size != PublicProfileBinary.PIN_BYTES) {
                throw PublicProfileException.InvalidFieldLength(PublicProfileField.TARGET_PIN)
            }
            return PublicProfilePin(digest)
        }
    }
}

class FixturePackageIdentity
private constructor(val packageName: String, val versionCode: Long, signerDigest: ByteArray) {
    private val stableSignerDigest = signerDigest.copyOf()

    val signerDigest: ByteArray
        get() = stableSignerDigest.copyOf()

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is FixturePackageIdentity &&
                packageName == other.packageName &&
                versionCode == other.versionCode &&
                MessageDigest.isEqual(stableSignerDigest, other.stableSignerDigest))

    override fun hashCode(): Int =
        31 * (31 * packageName.hashCode() + versionCode.hashCode()) +
            stableSignerDigest.contentHashCode()

    companion object {
        private val PACKAGE_NAME = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")

        fun create(
            packageName: String,
            versionCode: Long,
            signerDigest: ByteArray,
        ): FixturePackageIdentity {
            val encoded = packageName.toByteArray(StandardCharsets.UTF_8)
            if (
                encoded.size !in 1..PublicProfileBinary.MAX_PACKAGE_BYTES ||
                    !PACKAGE_NAME.matches(packageName) ||
                    versionCode <= 0 ||
                    signerDigest.size != PublicProfileBinary.SIGNER_DIGEST_BYTES
            ) {
                throw PublicProfileException.InvalidPackageIdentity()
            }
            return FixturePackageIdentity(packageName, versionCode, signerDigest)
        }
    }
}

class ProfileEndpoint private constructor(address: ByteArray, val port: Int) {
    private val addressBytes = address.copyOf()

    val address: ByteArray
        get() = addressBytes.copyOf()

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is ProfileEndpoint &&
                port == other.port &&
                addressBytes.contentEquals(other.addressBytes))

    override fun hashCode(): Int = 31 * addressBytes.contentHashCode() + port

    companion object {
        fun create(address: ByteArray, port: Int): ProfileEndpoint {
            val parsed =
                try {
                    InetAddress.getByAddress(address.copyOf())
                } catch (_: Exception) {
                    throw PublicProfileException.InvalidEndpoint()
                }
            if (address.size !in setOf(4, 16) || parsed.isMulticastAddress || port !in 1..65_535) {
                throw PublicProfileException.InvalidEndpoint()
            }
            return ProfileEndpoint(address, port)
        }
    }
}

sealed class ProvisionedPublicIdentity(
    val alias: String,
    certificateDer: ByteArray,
    val pin: PublicProfilePin,
    field: Int,
) {
    private val stableCertificateDer: ByteArray

    init {
        if (!VALID_ALIAS.matches(alias)) throw PublicProfileException.InvalidAlias()
        val certificate = validatePublicCertificate(field, certificateDer)
        if (certificate.pin != pin) throw PublicProfileException.PinMismatch(field)
        stableCertificateDer = certificate.der
    }

    val certificateDer: ByteArray
        get() = stableCertificateDer.copyOf()

    private companion object {
        val VALID_ALIAS = Regex("[A-Za-z0-9._-]{1,128}")
    }
}

class ProvisionedTargetIdentity
private constructor(alias: String, certificateDer: ByteArray, pin: PublicProfilePin) :
    ProvisionedPublicIdentity(alias, certificateDer, pin, PublicProfileField.TARGET_CERTIFICATE) {
    companion object {
        fun create(alias: String, certificateDer: ByteArray, pin: PublicProfilePin) =
            ProvisionedTargetIdentity(alias, certificateDer, pin)
    }
}

class ProvisionedDonorIdentity
private constructor(alias: String, certificateDer: ByteArray, pin: PublicProfilePin) :
    ProvisionedPublicIdentity(alias, certificateDer, pin, PublicProfileField.DONOR_CERTIFICATE) {
    companion object {
        fun create(alias: String, certificateDer: ByteArray, pin: PublicProfilePin) =
            ProvisionedDonorIdentity(alias, certificateDer, pin)
    }
}
