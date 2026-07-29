package org.matrix.teesimulator.twophone

sealed class PublicProfileException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class InvalidMagic : PublicProfileException("invalid public profile magic")

    class UnknownVersion(val version: Int) :
        PublicProfileException("unknown public profile version: $version")

    class Truncated : PublicProfileException("public profile is truncated")

    class TrailingData : PublicProfileException("public profile has trailing data")

    class DuplicateField(val field: Int) :
        PublicProfileException("duplicate public profile field: $field")

    class UnexpectedField(val field: Int) :
        PublicProfileException("unexpected public profile field: $field")

    class OversizedProfile : PublicProfileException("public profile exceeds the size limit")

    class OversizedField(val field: Int) :
        PublicProfileException("public profile field exceeds its size limit: $field")

    class InvalidFieldLength(val field: Int) :
        PublicProfileException("invalid public profile field length: $field")

    class InvalidUtf8(val field: Int) :
        PublicProfileException("invalid UTF-8 in public profile field: $field")

    class InvalidPackageIdentity : PublicProfileException("invalid fixture package identity")

    class InvalidEndpoint : PublicProfileException("invalid public profile endpoint")

    class InvalidAlias : PublicProfileException("invalid AndroidKeyStore alias")

    class InvalidCertificate(val field: Int, cause: Throwable? = null) :
        PublicProfileException("invalid public profile certificate: $field", cause)

    class PinMismatch(val field: Int) :
        PublicProfileException("public profile SPKI pin mismatch: $field")

    class CertificateMismatch(val field: Int) :
        PublicProfileException("public profile certificate mismatch: $field")

    class IdentityMismatch(val field: Int) :
        PublicProfileException("public profile identity mismatch: $field")

    class InvalidBounds : PublicProfileException("public profile operation bounds are not v1")
}

object PublicProfileLimits {
    const val MAX_OPERATIONS = 1
    const val DEADLINE_SECONDS = 120
}

object PublicProfileField {
    const val FIXTURE_PACKAGE = 1
    const val FIXTURE_VERSION = 2
    const val FIXTURE_SIGNER = 3
    const val DONOR_ENDPOINT = 4
    const val DONOR_TRUST_CHAIN = 5
    const val DONOR_PIN = 6
    const val TARGET_ALIAS = 7
    const val TARGET_CERTIFICATE = 8
    const val TARGET_PIN = 9
    const val MAX_OPERATIONS = 10
    const val DEADLINE_SECONDS = 11
    const val PAIR_TARGET_PIN = 12
    const val PAIR_DONOR_PIN = 13
    const val TARGET_TRUST_CHAIN = 14
    const val DONOR_ALIAS = 15
    const val DONOR_CERTIFICATE = 16
    const val BIND_ENDPOINT = 17

    val all =
        setOf(
            FIXTURE_PACKAGE,
            FIXTURE_VERSION,
            FIXTURE_SIGNER,
            DONOR_ENDPOINT,
            DONOR_TRUST_CHAIN,
            DONOR_PIN,
            TARGET_ALIAS,
            TARGET_CERTIFICATE,
            TARGET_PIN,
            MAX_OPERATIONS,
            DEADLINE_SECONDS,
            PAIR_TARGET_PIN,
            PAIR_DONOR_PIN,
            TARGET_TRUST_CHAIN,
            DONOR_ALIAS,
            DONOR_CERTIFICATE,
            BIND_ENDPOINT,
        )
}
