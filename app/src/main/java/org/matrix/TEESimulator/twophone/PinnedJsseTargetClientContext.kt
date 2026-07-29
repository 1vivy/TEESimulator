package org.matrix.TEESimulator.twophone

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.TargetPublicProfile

sealed class PinnedJsseTargetContextException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class InvalidIdentity(cause: Throwable? = null) :
        PinnedJsseTargetContextException("invalid target TLS client identity", cause)

    class InvalidTrust(cause: Throwable? = null) :
        PinnedJsseTargetContextException("invalid donor TLS trust material", cause)
}

internal class PinnedDonorCertificateException : CertificateException("donor SPKI pin mismatch")

object PinnedJsseTargetClientContext {
    fun create(identity: OpenedTargetTlsClientIdentity, profile: TargetPublicProfile): SSLContext {
        val expectedTargetPin = SpkiPin.parse(profile.targetIdentity.pin.toString())
        val expectedDonorPin = SpkiPin.parse(profile.donorPin.toString())
        if (identity.alias != profile.targetIdentity.alias || identity.pin != expectedTargetPin) {
            throw PinnedJsseTargetContextException.InvalidIdentity()
        }
        val delegate = keyManager(identity, expectedTargetPin)
        val trustManager = trustManager(profile, expectedDonorPin)
        return try {
            SSLContext.getInstance("TLS").apply {
                init(
                    arrayOf(RestrictedClientAliasKeyManager(delegate, identity.alias)),
                    arrayOf(trustManager),
                    SecureRandom(),
                )
            }
        } catch (failure: java.security.GeneralSecurityException) {
            throw PinnedJsseTargetContextException.InvalidIdentity(failure)
        }
    }

    private fun keyManager(
        identity: OpenedTargetTlsClientIdentity,
        expectedPin: SpkiPin,
    ): X509ExtendedKeyManager {
        val password = identity.keyPassword
        return try {
            val leaf = identity.keyStore.getCertificate(identity.alias) as? X509Certificate
            if (
                !identity.keyStore.isKeyEntry(identity.alias) ||
                    identity.keyStore.getKey(identity.alias, password) !is PrivateKey ||
                    leaf == null ||
                    !expectedPin.matches(leaf)
            ) {
                throw PinnedJsseTargetContextException.InvalidIdentity()
            }
            leaf.checkValidity()
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).run {
                init(identity.keyStore, password)
                keyManagers.filterIsInstance<X509ExtendedKeyManager>().single()
            }
        } catch (failure: PinnedJsseTargetContextException) {
            throw failure
        } catch (failure: Exception) {
            throw PinnedJsseTargetContextException.InvalidIdentity(failure)
        } finally {
            password?.fill('\u0000')
        }
    }

    private fun trustManager(
        profile: TargetPublicProfile,
        expectedPin: SpkiPin,
    ): X509ExtendedTrustManager {
        val trustStore =
            try {
                val rootDer = profile.donorTrustChainDer.last()
                val root =
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(rootDer.inputStream()) as X509Certificate
                KeyStore.getInstance("PKCS12").apply {
                    load(null, null)
                    setCertificateEntry("donor-root", root)
                }
            } catch (failure: Exception) {
                throw PinnedJsseTargetContextException.InvalidTrust(failure)
            }
        val delegate =
            try {
                TrustManagerFactory.getInstance("PKIX").run {
                    init(trustStore)
                    trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
                }
            } catch (failure: Exception) {
                throw PinnedJsseTargetContextException.InvalidTrust(failure)
            }
        return PinnedDonorTrustManager(delegate, expectedPin)
    }
}

private class RestrictedClientAliasKeyManager(
    private val delegate: X509ExtendedKeyManager,
    private val alias: String,
) : X509ExtendedKeyManager() {
    override fun chooseClientAlias(
        keyType: Array<out String>?,
        issuers: Array<out Principal>?,
        socket: Socket?,
    ): String? = if (keyType.orEmpty().any(::supports)) alias else null

    override fun chooseEngineClientAlias(
        keyType: Array<out String>?,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = if (keyType.orEmpty().any(::supports)) alias else null

    override fun getClientAliases(keyType: String, issuers: Array<out Principal>?): Array<String>? =
        if (supports(keyType)) arrayOf(alias) else null

    override fun getCertificateChain(alias: String): Array<X509Certificate>? =
        if (alias == this.alias) delegate.getCertificateChain(alias)?.copyOf() else null

    override fun getPrivateKey(alias: String): PrivateKey? =
        if (alias == this.alias) delegate.getPrivateKey(alias) else null

    override fun chooseServerAlias(
        keyType: String,
        issuers: Array<out Principal>?,
        socket: Socket?,
    ): String? = null

    override fun chooseEngineServerAlias(
        keyType: String,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = null

    override fun getServerAliases(keyType: String, issuers: Array<out Principal>?): Array<String>? =
        null

    private fun supports(keyType: String): Boolean {
        val algorithm = delegate.getPrivateKey(alias)?.algorithm ?: return false
        return keyType.equals(algorithm, ignoreCase = true) ||
            (algorithm.equals("EC", ignoreCase = true) && keyType.startsWith("EC"))
    }
}

private class PinnedDonorTrustManager(
    private val delegate: X509ExtendedTrustManager,
    private val expectedPin: SpkiPin,
) : X509ExtendedTrustManager() {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkServerTrusted(chain, authType)
        requirePin(chain)
    }

    override fun checkServerTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        socket: Socket,
    ) {
        delegate.checkServerTrusted(chain, authType, socket)
        requirePin(chain)
    }

    override fun checkServerTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        engine: SSLEngine,
    ) {
        delegate.checkServerTrusted(chain, authType, engine)
        requirePin(chain)
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)

    override fun checkClientTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        socket: Socket,
    ) = delegate.checkClientTrusted(chain, authType, socket)

    override fun checkClientTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        engine: SSLEngine,
    ) = delegate.checkClientTrusted(chain, authType, engine)

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers.copyOf()

    private fun requirePin(chain: Array<X509Certificate>) {
        val leaf = chain.firstOrNull() ?: throw CertificateException("empty donor chain")
        if (!expectedPin.matches(leaf)) throw PinnedDonorCertificateException()
    }
}
