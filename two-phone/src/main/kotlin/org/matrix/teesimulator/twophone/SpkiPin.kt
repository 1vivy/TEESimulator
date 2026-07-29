package org.matrix.teesimulator.twophone

import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64

sealed class SpkiPinException(message: String) : RuntimeException(message) {
    class InvalidFormat : SpkiPinException("invalid SPKI pin")
}

class SpkiPin private constructor(digest: ByteArray) {
    private val digestBytes = digest.copyOf()
    private val canonical = PREFIX + Base64.getEncoder().encodeToString(digestBytes)

    val digest: ByteArray
        get() = digestBytes.copyOf()

    fun matches(publicKey: PublicKey): Boolean =
        MessageDigest.isEqual(digestBytes, sha256(publicKey.encoded))

    fun matches(certificate: X509Certificate): Boolean = matches(certificate.publicKey)

    override fun toString(): String = canonical

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is SpkiPin && MessageDigest.isEqual(digestBytes, other.digestBytes))

    override fun hashCode(): Int = digestBytes.contentHashCode()

    companion object {
        private const val PREFIX = "sha256/"
        private const val DIGEST_BYTES = 32
        private const val CANONICAL_LENGTH = 51

        fun parse(value: String): SpkiPin {
            if (
                value.length != CANONICAL_LENGTH ||
                    !value.startsWith(PREFIX) ||
                    value.any { it.code > 0x7f }
            ) {
                invalidPin()
            }
            val decoded =
                try {
                    Base64.getDecoder().decode(value.substring(PREFIX.length))
                } catch (_: IllegalArgumentException) {
                    invalidPin()
                }
            if (decoded.size != DIGEST_BYTES) invalidPin()
            val pin = SpkiPin(decoded)
            if (pin.canonical != value) invalidPin()
            return pin
        }

        fun from(publicKey: PublicKey): SpkiPin = SpkiPin(sha256(publicKey.encoded))

        fun from(certificate: X509Certificate): SpkiPin = from(certificate.publicKey)

        private fun sha256(value: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(value)

        private fun invalidPin(): Nothing = throw SpkiPinException.InvalidFormat()
    }
}
