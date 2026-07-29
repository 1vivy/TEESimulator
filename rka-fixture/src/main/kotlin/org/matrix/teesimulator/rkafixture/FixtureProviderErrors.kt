package org.matrix.teesimulator.rkafixture

enum class FixtureProviderErrorCode {
    UNAUTHORIZED_UID,
    UNVERIFIED_ATTRIBUTION,
    CROSS_USER_ADDRESS,
    INVALID_AUTHORITY,
    INVALID_ROUTE,
    UNSUPPORTED_VERSION,
    INVALID_MODE,
    INVALID_NONCE,
    MALFORMED_REQUEST,
    OVERSIZED_REQUEST,
    DUPLICATE_UPLOAD,
    UPLOAD_TIMEOUT,
    UPLOAD_INTERRUPTED,
    MISSING_REQUEST,
    DUPLICATE_EXECUTE,
}

sealed class FixtureProviderError(val code: FixtureProviderErrorCode) :
    IllegalArgumentException(code.name) {
    data object UnauthorizedUid : FixtureProviderError(FixtureProviderErrorCode.UNAUTHORIZED_UID)

    data object UnverifiedAttribution :
        FixtureProviderError(FixtureProviderErrorCode.UNVERIFIED_ATTRIBUTION)

    data object CrossUserAddress : FixtureProviderError(FixtureProviderErrorCode.CROSS_USER_ADDRESS)

    data object InvalidAuthority : FixtureProviderError(FixtureProviderErrorCode.INVALID_AUTHORITY)

    data object InvalidRoute : FixtureProviderError(FixtureProviderErrorCode.INVALID_ROUTE)

    data object UnsupportedVersion :
        FixtureProviderError(FixtureProviderErrorCode.UNSUPPORTED_VERSION)

    data object InvalidMode : FixtureProviderError(FixtureProviderErrorCode.INVALID_MODE)

    data object InvalidNonce : FixtureProviderError(FixtureProviderErrorCode.INVALID_NONCE)

    data object MalformedRequest : FixtureProviderError(FixtureProviderErrorCode.MALFORMED_REQUEST)

    data object OversizedRequest : FixtureProviderError(FixtureProviderErrorCode.OVERSIZED_REQUEST)

    data object DuplicateUpload : FixtureProviderError(FixtureProviderErrorCode.DUPLICATE_UPLOAD)

    data object UploadTimeout : FixtureProviderError(FixtureProviderErrorCode.UPLOAD_TIMEOUT)

    data object UploadInterrupted :
        FixtureProviderError(FixtureProviderErrorCode.UPLOAD_INTERRUPTED)

    data object MissingRequest : FixtureProviderError(FixtureProviderErrorCode.MISSING_REQUEST)

    data object DuplicateExecute : FixtureProviderError(FixtureProviderErrorCode.DUPLICATE_EXECUTE)
}
