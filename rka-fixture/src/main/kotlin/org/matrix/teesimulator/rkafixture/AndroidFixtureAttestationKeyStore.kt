package org.matrix.teesimulator.rkafixture

import android.security.KeyStoreException
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class AndroidFixtureAttestationKeyStore : FixtureAttestationKeyStore {
    override fun generate(alias: String, challenge: ByteArray): FixtureAttestedKeyMaterial =
        classify {
            val pairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
            pairGenerator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .setAttestationChallenge(challenge.copyOf())
                    .build()
            )
            pairGenerator.generateKeyPair()
            val chain = keyStore().getCertificateChain(alias)?.toList().orEmpty()
            if (chain.isEmpty())
                throw IllegalStateException("AndroidKeyStore did not return a certificate chain")
            return FixtureAttestedKeyMaterial(chain.map { it.encoded }, chain.first().publicKey)
        }

    override fun sign(alias: String, payload: ByteArray): ByteArray = classify {
        val privateKey =
            keyStore().getKey(alias, null) as? PrivateKey
                ?: throw IllegalStateException("missing key")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(payload.copyOf())
            sign()
        }
    }

    override fun delete(alias: String) = classify { keyStore().deleteEntry(alias) }

    private inline fun <T> classify(action: () -> T): T =
        try {
            action()
        } catch (failure: FixtureKeyStoreBackendFailure) {
            throw failure
        } catch (failure: Exception) {
            throw FixtureKeyStoreBackendFailure(diagnostic(failure), failure)
        }

    private fun diagnostic(failure: Throwable): FixtureKeyStoreDiagnostic {
        var current: Throwable? = failure
        while (current != null) {
            if (current is KeyStoreException) {
                return FixtureKeyStoreDiagnostic(
                    FixtureKeyStoreFailureCategory.PROVIDER_FAILURE,
                    current.numericErrorCode,
                )
            }
            current = current.cause
        }
        return when (failure) {
            is KeyPermanentlyInvalidatedException ->
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.KEY_INVALIDATED, 0)
            is InvalidAlgorithmParameterException ->
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.UNSUPPORTED_PARAMETERS, 0)
            is SecurityException ->
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.PERMISSION, 0)
            is ProviderException ->
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.PROVIDER_FAILURE, 0)
            else -> FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.UNKNOWN, 0)
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val P256_CURVE = "secp256r1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
