package org.matrix.teesimulator.rkahost.evidence

import java.security.KeyPairGenerator

object ReceiptTestKeys {
    private val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    val signer = Ed25519ReceiptSigner("test-key", keyPair.private)
    val trustedKeys = mapOf(signer.keyId to keyPair.public)
}
