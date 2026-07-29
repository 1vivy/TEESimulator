package org.matrix.teesimulator.rkafixture

enum class FixtureKeyStoreFailureCategory {
    UNSUPPORTED_PARAMETERS,
    ATTESTATION_UNAVAILABLE,
    PERMISSION,
    ALIAS_COLLISION,
    KEY_INVALIDATED,
    PROVIDER_FAILURE,
    UNKNOWN,
}

data class FixtureKeyStoreDiagnostic(
    val category: FixtureKeyStoreFailureCategory,
    val numericCode: Int,
)

class FixtureKeyStoreBackendFailure(val diagnostic: FixtureKeyStoreDiagnostic, cause: Throwable) :
    IllegalStateException("fixture keystore backend failure", cause)
