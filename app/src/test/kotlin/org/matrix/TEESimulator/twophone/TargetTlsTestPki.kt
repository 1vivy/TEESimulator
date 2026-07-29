package org.matrix.TEESimulator.twophone

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class TargetTlsTestPki {
    private var serial = 1L
    private val now = Instant.now()

    fun root(name: String): TargetTlsTestIdentity {
        val keys = keyPair()
        val subject = X500Name("CN=$name")
        val certificate = certificate(subject, subject, keys, keys, isCa = true, serverIp = null)
        return TargetTlsTestIdentity(keys, certificate, certificate)
    }

    fun client(name: String, root: TargetTlsTestIdentity): TargetTlsTestIdentity =
        leaf(name, root, serverIp = null)

    fun server(
        name: String,
        root: TargetTlsTestIdentity,
        serverIp: String?,
    ): TargetTlsTestIdentity = leaf(name, root, serverIp)

    fun keyStore(alias: String, identity: TargetTlsTestIdentity): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            load(null, PASSWORD)
            setKeyEntry(
                alias,
                identity.keyPair.private,
                PASSWORD,
                arrayOf(identity.certificate, identity.rootCertificate),
            )
        }

    fun trustStore(root: TargetTlsTestIdentity): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            load(null, PASSWORD)
            setCertificateEntry("root", root.certificate)
        }

    private fun leaf(
        name: String,
        root: TargetTlsTestIdentity,
        serverIp: String?,
    ): TargetTlsTestIdentity {
        val keys = keyPair()
        val certificate =
            certificate(
                X500Name(root.certificate.subjectX500Principal.name),
                X500Name("CN=$name"),
                keys,
                root.keyPair,
                isCa = false,
                serverIp,
            )
        return TargetTlsTestIdentity(keys, certificate, root.certificate)
    }

    private fun certificate(
        issuer: X500Name,
        subject: X500Name,
        subjectKeys: KeyPair,
        issuerKeys: KeyPair,
        isCa: Boolean,
        serverIp: String?,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(serial++),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
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
                    if (serverIp == null) KeyPurposeId.id_kp_clientAuth
                    else KeyPurposeId.id_kp_serverAuth
                ),
            )
            if (serverIp != null) {
                builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    GeneralNames(GeneralName(GeneralName.iPAddress, serverIp)),
                )
            }
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    companion object {
        val PASSWORD = "target-tls-test".toCharArray()
    }
}

internal data class TargetTlsTestIdentity(
    val keyPair: KeyPair,
    val certificate: X509Certificate,
    val rootCertificate: X509Certificate,
)
