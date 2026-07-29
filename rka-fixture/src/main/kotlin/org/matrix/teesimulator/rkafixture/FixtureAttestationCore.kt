package org.matrix.teesimulator.rkafixture

import java.security.PublicKey
import java.security.SecureRandom
import java.util.Base64

interface FixtureAttestationKeyStore {
    fun generate(alias: String, challenge: ByteArray): FixtureAttestedKeyMaterial

    fun sign(alias: String, payload: ByteArray): ByteArray

    fun delete(alias: String)
}

class FixtureAttestedKeyMaterial(certificateChainDer: List<ByteArray>, val publicKey: PublicKey) {
    private val chain = certificateChainDer.map(ByteArray::copyOf)

    val certificateChainDer: List<ByteArray>
        get() = chain.map(ByteArray::copyOf)
}

class FixtureAttestationResult(
    certificateChainDer: List<ByteArray>,
    payload: ByteArray,
    signature: ByteArray,
) {
    private val chain = certificateChainDer.map(ByteArray::copyOf)
    private val signedPayload = payload.copyOf()
    private val signatureBytes = signature.copyOf()

    val certificateChainDer: List<ByteArray>
        get() = chain.map(ByteArray::copyOf)

    val payload: ByteArray
        get() = signedPayload.copyOf()

    val signature: ByteArray
        get() = signatureBytes.copyOf()
}

interface FixtureCore {
    fun attestAndSign(
        activation: FixtureRoleActivation,
        challenge: ByteArray,
    ): FixtureAttestationResult
}

sealed class FixtureCoreError(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class InvalidChallenge : FixtureCoreError("attestation challenge must be exactly 32 bytes")

    class KeyStoreOperation(val diagnostic: FixtureKeyStoreDiagnostic, cause: Throwable) :
        FixtureCoreError("fixture keystore operation failed", cause)

    class AliasCleanup(primary: Throwable?, cleanup: Throwable) :
        FixtureCoreError("fixture ephemeral alias cleanup failed", primary ?: cleanup) {
        init {
            if (primary != null) addSuppressed(cleanup)
        }
    }
}

class FixtureAttestationCore(
    private val keyStore: FixtureAttestationKeyStore,
    private val secureRandom: SecureRandom,
) : FixtureCore {
    override fun attestAndSign(
        activation: FixtureRoleActivation,
        challenge: ByteArray,
    ): FixtureAttestationResult {
        requireRole(activation)
        if (challenge.size != FixtureAttestationChallenge.BYTES)
            throw FixtureCoreError.InvalidChallenge()
        val alias = freshAlias()
        var primaryFailure: Throwable? = null
        try {
            val material = keyStoreOperation { keyStore.generate(alias, challenge.copyOf()) }
            val payload = ByteArray(PAYLOAD_BYTES).also(secureRandom::nextBytes)
            val signature = keyStoreOperation { keyStore.sign(alias, payload.copyOf()) }
            return FixtureAttestationResult(material.certificateChainDer, payload, signature)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                keyStore.delete(alias)
            } catch (cleanupFailure: Exception) {
                throw FixtureCoreError.AliasCleanup(primaryFailure, cleanupFailure)
            }
        }
    }

    private fun requireRole(activation: FixtureRoleActivation) {
        when (activation.role) {
            FixtureRole.DONOR,
            FixtureRole.TARGET -> Unit
        }
    }

    private fun freshAlias(): String {
        val random = ByteArray(ALIAS_RANDOM_BYTES).also(secureRandom::nextBytes)
        return "rka_fixture_v1_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random)
    }

    private inline fun <T> keyStoreOperation(operation: () -> T): T =
        try {
            operation()
        } catch (failure: FixtureKeyStoreBackendFailure) {
            throw FixtureCoreError.KeyStoreOperation(failure.diagnostic, failure)
        } catch (failure: FixtureCoreError) {
            throw failure
        } catch (failure: Exception) {
            throw FixtureCoreError.KeyStoreOperation(
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.UNKNOWN, 0),
                failure,
            )
        }

    private companion object {
        const val ALIAS_RANDOM_BYTES = 16
        const val PAYLOAD_BYTES = 32
    }
}
