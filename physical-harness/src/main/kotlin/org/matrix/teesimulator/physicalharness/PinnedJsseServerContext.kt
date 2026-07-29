package org.matrix.teesimulator.physicalharness

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import org.matrix.teesimulator.twophone.SpkiPin

sealed class PinnedJsseContextException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class InvalidIdentity(cause: Throwable? = null) :
        PinnedJsseContextException("invalid TLS identity", cause)

    class InvalidTrust(cause: Throwable? = null) :
        PinnedJsseContextException("invalid TLS trust material", cause)
}

object PinnedJsseServerContext {
    fun create(
        keyStore: KeyStore,
        privateKeyAlias: String,
        privateKeyPassword: CharArray?,
        expectedDonorPin: SpkiPin,
        targetTrustAnchors: KeyStore,
    ): SSLContext {
        val leaf = selectedLeaf(keyStore, privateKeyAlias, privateKeyPassword)
        if (!expectedDonorPin.matches(leaf)) throw PinnedJsseContextException.InvalidIdentity()
        val delegate =
            try {
                withPasswordCopy(privateKeyPassword) { password ->
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).run {
                        init(keyStore, password)
                        keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
                    }
                }
            } catch (failure: RuntimeException) {
                throw PinnedJsseContextException.InvalidIdentity(failure)
            } catch (failure: java.security.GeneralSecurityException) {
                throw PinnedJsseContextException.InvalidIdentity(failure)
            }
        val trustManagers =
            try {
                TrustManagerFactory.getInstance("PKIX").run {
                    init(targetTrustAnchors)
                    trustManagers
                }
            } catch (failure: java.security.GeneralSecurityException) {
                throw PinnedJsseContextException.InvalidTrust(failure)
            }
        return try {
            SSLContext.getInstance("TLS").apply {
                init(
                    arrayOf(RestrictedServerAliasKeyManager(delegate, privateKeyAlias)),
                    trustManagers,
                    SecureRandom(),
                )
            }
        } catch (failure: java.security.GeneralSecurityException) {
            throw PinnedJsseContextException.InvalidIdentity(failure)
        }
    }

    private fun selectedLeaf(
        keyStore: KeyStore,
        alias: String,
        password: CharArray?,
    ): X509Certificate =
        try {
            if (!keyStore.isKeyEntry(alias)) throw PinnedJsseContextException.InvalidIdentity()
            withPasswordCopy(password) { keyStore.getKey(alias, it) } as? PrivateKey
                ?: throw PinnedJsseContextException.InvalidIdentity()
            (keyStore.getCertificate(alias) as? X509Certificate)?.also(
                X509Certificate::checkValidity
            ) ?: throw PinnedJsseContextException.InvalidIdentity()
        } catch (failure: PinnedJsseContextException) {
            throw failure
        } catch (failure: Exception) {
            throw PinnedJsseContextException.InvalidIdentity(failure)
        }

    private inline fun <T> withPasswordCopy(password: CharArray?, block: (CharArray?) -> T): T {
        val copy = password?.copyOf()
        return try {
            block(copy)
        } finally {
            copy?.fill('\u0000')
        }
    }
}

private class RestrictedServerAliasKeyManager(
    private val delegate: X509ExtendedKeyManager,
    private val alias: String,
) : X509ExtendedKeyManager() {
    override fun chooseServerAlias(
        keyType: String,
        issuers: Array<out Principal>?,
        socket: Socket?,
    ): String? = if (supports(keyType)) alias else null

    override fun chooseEngineServerAlias(
        keyType: String,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = if (supports(keyType)) alias else null

    override fun getServerAliases(keyType: String, issuers: Array<out Principal>?): Array<String>? =
        if (supports(keyType)) arrayOf(alias) else null

    override fun getCertificateChain(alias: String): Array<X509Certificate>? =
        if (alias == this.alias) delegate.getCertificateChain(alias)?.copyOf() else null

    override fun getPrivateKey(alias: String): PrivateKey? =
        if (alias == this.alias) delegate.getPrivateKey(alias) else null

    override fun chooseClientAlias(
        keyType: Array<out String>?,
        issuers: Array<out Principal>?,
        socket: Socket?,
    ): String? = delegate.chooseClientAlias(keyType, issuers, socket)

    override fun chooseEngineClientAlias(
        keyType: Array<out String>?,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = delegate.chooseEngineClientAlias(keyType, issuers, engine)

    override fun getClientAliases(keyType: String, issuers: Array<out Principal>?): Array<String>? =
        delegate.getClientAliases(keyType, issuers)?.copyOf()

    private fun supports(keyType: String): Boolean {
        val privateKey = delegate.getPrivateKey(alias) ?: return false
        return keyType.equals(privateKey.algorithm, ignoreCase = true) ||
            (privateKey.algorithm.equals("EC", ignoreCase = true) && keyType.startsWith("EC"))
    }
}
