package org.matrix.teesimulator.physicalharness

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class TlsTestPki {
    private var serial = 1L
    private val now = Instant.now()

    fun root(
        name: String,
        notBefore: Instant = now.minus(1, ChronoUnit.DAYS),
        notAfter: Instant = now.plus(1, ChronoUnit.DAYS),
    ): TlsTestIdentity {
        val keyPair = keyPair()
        val subject = X500Name("CN=$name")
        val certificate =
            certificateBuilder(
                subject,
                subject,
                keyPair,
                keyPair,
                isCa = true,
                server = false,
                notBefore = notBefore,
                notAfter = notAfter,
            )
        return TlsTestIdentity(keyPair, certificate, certificate)
    }

    fun leaf(name: String, issuer: TlsTestIdentity, server: Boolean): TlsTestIdentity {
        val keyPair = keyPair()
        val certificate =
            certificateBuilder(
                X500Name(issuer.certificate.subjectX500Principal.name),
                X500Name("CN=$name"),
                keyPair,
                issuer.keyPair,
                isCa = false,
                server = server,
                notBefore = now.minus(1, ChronoUnit.DAYS),
                notAfter = now.plus(1, ChronoUnit.DAYS),
            )
        return TlsTestIdentity(keyPair, certificate, issuer.certificate)
    }

    fun keyStore(vararg entries: Pair<String, TlsTestIdentity>): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            load(null, PASSWORD)
            entries.forEach { (alias, identity) ->
                setKeyEntry(
                    alias,
                    identity.keyPair.private,
                    PASSWORD,
                    arrayOf(identity.certificate, identity.rootCertificate),
                )
            }
        }

    fun trustStore(vararg roots: TlsTestIdentity): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            load(null, PASSWORD)
            roots.forEachIndexed { index, root ->
                setCertificateEntry("root-$index", root.certificate)
            }
        }

    fun clientContext(identity: TlsTestIdentity?, trustedRoot: TlsTestIdentity): SSLContext {
        val keyManagers =
            identity?.let {
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).run {
                    init(keyStore("client" to identity), PASSWORD)
                    keyManagers
                }
            }
        val trustManagers =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
                init(trustStore(trustedRoot))
                trustManagers
            }
        return SSLContext.getInstance("TLS").apply {
            init(keyManagers, trustManagers, SecureRandom())
        }
    }

    private fun certificateBuilder(
        issuer: X500Name,
        subject: X500Name,
        subjectKeys: KeyPair,
        issuerKeys: KeyPair,
        isCa: Boolean,
        server: Boolean,
        notBefore: Instant,
        notAfter: Instant,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(serial++),
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                subjectKeys.public,
            )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
        builder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(if (isCa) KeyUsage.keyCertSign else KeyUsage.digitalSignature),
        )
        if (!isCa) {
            builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(
                    if (server) KeyPurposeId.id_kp_serverAuth else KeyPurposeId.id_kp_clientAuth
                ),
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer)).also {
            it.verify(issuerKeys.public)
        }
    }

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    companion object {
        val PASSWORD = "test-password".toCharArray()
    }
}

internal data class TlsTestIdentity(
    val keyPair: KeyPair,
    val certificate: X509Certificate,
    val rootCertificate: X509Certificate,
)
