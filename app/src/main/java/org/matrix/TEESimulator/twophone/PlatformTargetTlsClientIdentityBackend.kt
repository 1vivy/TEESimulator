package org.matrix.TEESimulator.twophone

import android.os.Process
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

internal class PlatformTargetTlsClientIdentityBackend : TargetTlsClientIdentityBackend {
    override fun containsAlias(alias: String): Boolean = keyStore().containsAlias(alias)

    override fun generate(alias: String, spec: TargetTlsClientGenerationSpec) {
        synchronized(keyStoreMutationLock) {
            if (keyStore().containsAlias(alias)) {
                throw TargetTlsClientIdentityException.AliasAlreadyExists()
            }
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

    override fun load(alias: String): TargetTlsClientBackendMaterial? {
        val store = keyStore()
        if (!store.containsAlias(alias)) return null
        val key = store.getKey(alias, null)
        val securityLevel =
            if (key is PrivateKey) {
                KeyFactory.getInstance(key.algorithm, ANDROID_KEY_STORE)
                    .getKeySpec(key, KeyInfo::class.java)
                    .securityLevel
                    .toTargetSecurityLevel()
            } else {
                TargetTlsSecurityLevel.UNKNOWN
            }
        val chain =
            store.getCertificateChain(alias)?.toList()
                ?: store.getCertificate(alias)?.let(::listOf)
                ?: emptyList()
        return TargetTlsClientBackendMaterial(
            key,
            Process.myUid(),
            securityLevel,
            chain,
            store,
            null,
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
        synchronized(keyStoreMutationLock) { keyStore().deleteEntry(alias) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        val keyStoreMutationLock = Any()
    }
}

private fun Int.toTargetSecurityLevel(): TargetTlsSecurityLevel =
    when (this) {
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
            TargetTlsSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> TargetTlsSecurityLevel.SOFTWARE
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> TargetTlsSecurityLevel.STRONGBOX
        else -> TargetTlsSecurityLevel.UNKNOWN
    }
