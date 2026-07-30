package org.matrix.teesimulator.rkafixture

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey

object CandidateKeystoreCaller {
    fun generateEcSigningKey(alias: String): CandidateKeyMaterial {
        require(alias.matches(aliasPattern)) { "FIXTURE_ALIAS_INVALID" }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.deleteEntry(alias)
        val pair =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply {
                    initialize(
                        KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                            )
                            .setAlgorithmParameterSpec(
                                java.security.spec.ECGenParameterSpec("secp256r1")
                            )
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build()
                    )
                }
                .generateKeyPair()
        return CandidateKeyMaterial(pair.private, pair.public)
    }

    fun delete(alias: String) {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(alias)
        }
    }

    private val aliasPattern = Regex("teesim_rka_fixture_[a-z0-9_]{1,64}")
}

data class CandidateKeyMaterial(val privateKey: PrivateKey, val publicKey: PublicKey)
