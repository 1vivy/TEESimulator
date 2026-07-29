package org.matrix.TEESimulator.interception.policy

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.ProfileEndpoint
import org.matrix.teesimulator.twophone.ProvisionedTargetIdentity
import org.matrix.teesimulator.twophone.PublicProfilePin
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.TargetPublicProfile

class InstalledTargetProfileApprovedFixtureSourceTest {
    private val fixtureIdentity =
        FixturePackageIdentity.create(
            "org.matrix.teesimulator.rkafixture",
            7L,
            ByteArray(32) { index -> (index + 11).toByte() },
        )
    private val donorRoot = root("donor-root")
    private val donorLeaf = leaf("donor", donorRoot)
    private val targetLeaf = leaf("target", donorRoot)
    private val targetProfile =
        TargetPublicProfile.create(
            fixtureIdentity,
            ProfileEndpoint.create(byteArrayOf(10, 0, 0, 7), 5555),
            listOf(donorLeaf.certificate.encoded, donorRoot.certificate.encoded),
            PublicProfilePin.fromCertificate(donorLeaf.certificate.encoded),
            ProvisionedTargetIdentity.create(
                "target-tls-v1",
                targetLeaf.certificate.encoded,
                PublicProfilePin.fromCertificate(targetLeaf.certificate.encoded),
            ),
        )

    @Test
    fun loadsApprovedFixtureProfileFromTargetProfileBytes() {
        val encoded = PublicProfileCodec.encodeTarget(targetProfile)

        val approved = InstalledTargetProfileApprovedFixtureSource { encoded }.load()

        requireNotNull(approved)
        assertEquals(fixtureIdentity.packageName, approved.packageName)
        assertEquals(fixtureIdentity.versionCode, approved.versionCode)
        assertEquals(fixtureIdentity.signerDigest.toHex(), approved.signerDigest.hex)
    }

    @Test
    fun malformedOrMissingTargetProfileFailsClosed() {
        assertNull(InstalledTargetProfileApprovedFixtureSource { null }.load())
        assertNull(InstalledTargetProfileApprovedFixtureSource { byteArrayOf(1, 2, 3) }.load())
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun root(name: String): TestIdentity {
        val keys = keyPair()
        val subject = X500Name("CN=$name")
        return TestIdentity(keys, certificate(subject, subject, keys, keys, true))
    }

    private fun leaf(name: String, issuer: TestIdentity): TestIdentity {
        val keys = keyPair()
        return TestIdentity(
            keys,
            certificate(
                X500Name(issuer.certificate.subjectX500Principal.name),
                X500Name("CN=$name"),
                keys,
                issuer.keyPair,
                false,
            ),
        )
    }

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    private fun certificate(
        issuer: X500Name,
        subject: X500Name,
        subjectKeys: KeyPair,
        issuerKeys: KeyPair,
        isCa: Boolean,
    ): X509Certificate {
        val now = Instant.now()
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(kotlin.math.abs(subject.hashCode().toLong()) + 1L),
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
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer)).also {
            it.verify(issuerKeys.public)
        }
    }

    private data class TestIdentity(val keyPair: KeyPair, val certificate: X509Certificate)
}
