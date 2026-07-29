package org.matrix.teesimulator.physicalharness

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal class PlatformAndroidKeyStoreBackend : AndroidKeyStoreBackend {
    override fun aliases(): Set<String> = platformCall {
        val aliases = loadKeyStore().aliases()
        buildSet { while (aliases.hasMoreElements()) add(aliases.nextElement()) }
    }

    override fun containsAlias(alias: String): Boolean = platformCall {
        loadKeyStore().containsAlias(alias)
    }

    override fun generate(alias: String, challenge: ByteArray): BackendKeyMaterial =
        synchronized(keyStoreMutationLock) {
            val keyStore = loadKeyStore()
            if (platformCall { keyStore.containsAlias(alias) }) {
                throw AndroidKeystoreDonorException.AliasAlreadyExists()
            }
            val keyPair = platformCall {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
                    .apply {
                        initialize(
                            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                                .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setAttestationChallenge(challenge.copyOf())
                                .setUserAuthenticationRequired(false)
                                .setIsStrongBoxBacked(false)
                                .build()
                        )
                    }
                    .generateKeyPair()
            }
            try {
                material(
                    keyStore = loadKeyStore(),
                    alias = alias,
                    privateKey = keyPair.private,
                    generatedPublicKey = keyPair.public.encoded,
                )
            } catch (failure: RuntimeException) {
                cleanupGeneratedAlias(alias, failure)
            }
        }

    override fun metadata(alias: String): BackendKeyMaterial? {
        val keyStore = loadKeyStore()
        if (!platformCall { keyStore.containsAlias(alias) }) return null
        val privateKey =
            platformCall { keyStore.getKey(alias, null) } as? PrivateKey
                ?: throw AndroidKeystoreDonorException.BackendFailure(
                    GeneralSecurityException("AndroidKeyStore entry is not a private key")
                )
        val publicKey =
            platformCall { keyStore.getCertificate(alias)?.publicKey?.encoded }
                ?: throw AndroidKeystoreDonorException.BackendFailure(
                    GeneralSecurityException("AndroidKeyStore certificate is missing")
                )
        return material(keyStore, alias, privateKey, publicKey)
    }

    override fun delete(alias: String) {
        synchronized(keyStoreMutationLock) { platformCall { loadKeyStore().deleteEntry(alias) } }
    }

    override fun begin(alias: String): BackendSignOperation {
        val keyStore = loadKeyStore()
        val privateKey =
            platformCall { keyStore.getKey(alias, null) } as? PrivateKey
                ?: throw AndroidKeystoreDonorException.KeyNotFound()
        val signature = platformCall {
            Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey) }
        }
        return PlatformSignOperation(signature)
    }

    private fun material(
        keyStore: KeyStore,
        alias: String,
        privateKey: PrivateKey,
        generatedPublicKey: ByteArray,
    ): BackendKeyMaterial {
        val keyInfo = platformCall {
            KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
                .getKeySpec(privateKey, KeyInfo::class.java)
        }
        val certificateChain = platformCall {
            keyStore.getCertificateChain(alias)?.map { certificate -> certificate.encoded }
                ?: emptyList()
        }
        return BackendKeyMaterial(
            securityLevel = keyInfo.securityLevel.toBackendSecurityLevel(),
            generatedPublicKey = generatedPublicKey,
            certificateChain = certificateChain,
        )
    }

    private fun cleanupGeneratedAlias(alias: String, failure: RuntimeException): Nothing {
        try {
            platformCall { loadKeyStore().deleteEntry(alias) }
        } catch (cleanupFailure: RuntimeException) {
            failure.addSuppressed(cleanupFailure)
        }
        throw failure
    }

    private fun loadKeyStore(): KeyStore = platformCall {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
    }

    private class PlatformSignOperation(private val signature: Signature) : BackendSignOperation {
        private var active = true

        @Synchronized
        override fun update(input: ByteArray) {
            requireActive()
            try {
                platformCall { signature.update(input) }
            } catch (failure: RuntimeException) {
                active = false
                throw failure
            }
        }

        @Synchronized
        override fun finish(input: ByteArray): ByteArray {
            requireActive()
            return try {
                platformCall {
                    signature.update(input)
                    signature.sign()
                }
            } finally {
                active = false
            }
        }

        @Synchronized
        override fun abort() {
            active = false
        }

        private fun requireActive() {
            if (!active) {
                throw AndroidKeystoreDonorException.BackendFailure(
                    GeneralSecurityException("signature operation is terminal")
                )
            }
        }
    }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val P256_CURVE = "secp256r1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        val keyStoreMutationLock = Any()
    }
}

private fun Int.toBackendSecurityLevel(): BackendSecurityLevel =
    when (this) {
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> BackendSecurityLevel.SOFTWARE
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> BackendSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> BackendSecurityLevel.STRONGBOX
        else -> BackendSecurityLevel.UNKNOWN
    }

private inline fun <T> platformCall(block: () -> T): T =
    try {
        block()
    } catch (exception: GeneralSecurityException) {
        throw AndroidKeystoreDonorException.BackendFailure(exception)
    } catch (exception: IOException) {
        throw AndroidKeystoreDonorException.BackendFailure(exception)
    } catch (exception: ProviderException) {
        throw AndroidKeystoreDonorException.BackendFailure(exception)
    }
