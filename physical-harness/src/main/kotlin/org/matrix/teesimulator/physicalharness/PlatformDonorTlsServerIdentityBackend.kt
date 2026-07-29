package org.matrix.teesimulator.physicalharness

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal class PlatformDonorTlsServerIdentityBackend : DonorTlsServerIdentityBackend {
    override fun containsAlias(alias: String): Boolean = loadKeyStore().containsAlias(alias)

    override fun generate(alias: String, spec: DonorTlsServerGenerationSpec) {
        synchronized(keyStoreMutationLock) {
            if (loadKeyStore().containsAlias(alias)) {
                throw DonorTlsServerIdentityException.AliasAlreadyExists()
            }
            require(spec.purposes == setOf(DonorTlsServerKeyPurpose.SIGN))
            require(spec.attestationChallenge == null)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
                .apply {
                    initialize(
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec(spec.curve))
                            .setDigests(spec.digest)
                            .setUserAuthenticationRequired(spec.userAuthenticationRequired)
                            .setIsStrongBoxBacked(spec.strongBoxBacked)
                            .setCertificateSubject(spec.certificateSubject)
                            .setCertificateSerialNumber(spec.certificateSerialNumber)
                            .setCertificateNotBefore(spec.certificateNotBefore)
                            .setCertificateNotAfter(spec.certificateNotAfter)
                            .build()
                    )
                }
                .generateKeyPair()
        }
    }

    override fun load(alias: String): DonorTlsServerBackendMaterial? {
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(alias)) return null
        val key = keyStore.getKey(alias, null)
        val securityLevel =
            if (key is PrivateKey) {
                KeyFactory.getInstance(key.algorithm, ANDROID_KEY_STORE)
                    .getKeySpec(key, KeyInfo::class.java)
                    .securityLevel
                    .toDonorTlsSecurityLevel()
            } else {
                BackendSecurityLevel.UNKNOWN
            }
        val chain =
            keyStore.getCertificateChain(alias)?.toList()
                ?: keyStore.getCertificate(alias)?.let(::listOf)
                ?: emptyList()
        return DonorTlsServerBackendMaterial(
            key = key,
            securityLevel = securityLevel,
            certificateChain = chain,
            keyStore = keyStore,
            keyPassword = null,
        )
    }

    override fun signProbe(privateKey: PrivateKey, input: ByteArray): ByteArray =
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(input)
            sign()
        }

    override fun verifyProbe(
        publicKey: PublicKey,
        input: ByteArray,
        signature: ByteArray,
    ): Boolean =
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(publicKey)
            update(input)
            verify(signature)
        }

    override fun delete(alias: String) {
        synchronized(keyStoreMutationLock) { loadKeyStore().deleteEntry(alias) }
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        val keyStoreMutationLock = Any()
    }
}

private fun Int.toDonorTlsSecurityLevel(): BackendSecurityLevel =
    when (this) {
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> BackendSecurityLevel.SOFTWARE
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> BackendSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> BackendSecurityLevel.STRONGBOX
        else -> BackendSecurityLevel.UNKNOWN
    }
