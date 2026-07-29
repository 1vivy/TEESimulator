package org.matrix.teesimulator.twophone

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class PublicProfileTestFixture {
    private val pki = PublicProfileTestPki()
    val targetRoot = pki.root("target-root")
    val target = pki.leaf("target", targetRoot)
    val otherTarget = pki.leaf("other-target", targetRoot)
    val donorRoot = pki.root("donor-root")
    val donor = pki.leaf("donor", donorRoot)
    val otherDonor = pki.leaf("other-donor", donorRoot)
    val fixtureIdentity = FixturePackageIdentity.create("fixture.runtime", 7L, profileBytes(32, 41))
    val targetIdentity =
        ProvisionedTargetIdentity.create(
            "target-tls-v1",
            target.certificate.encoded,
            PublicProfilePin.fromCertificate(target.certificate.encoded),
        )
    val donorIdentity =
        ProvisionedDonorIdentity.create(
            "donor-tls-v1",
            donor.certificate.encoded,
            PublicProfilePin.fromCertificate(donor.certificate.encoded),
        )

    fun targetProfile(
        fixture: FixturePackageIdentity = fixtureIdentity,
        donorChain: List<ByteArray> =
            listOf(donor.certificate.encoded, donorRoot.certificate.encoded),
        donorPin: PublicProfilePin = donorIdentity.pin,
    ): TargetPublicProfile =
        TargetPublicProfile.create(
            fixture,
            ProfileEndpoint.create(profileBytes(4, 1), 42_321),
            donorChain,
            donorPin,
            targetIdentity,
        )

    fun donorProfile(
        targetProfile: TargetPublicProfile = targetProfile(),
        targetChain: List<ByteArray> =
            listOf(target.certificate.encoded, targetRoot.certificate.encoded),
        donor: ProvisionedDonorIdentity = donorIdentity,
    ): DonorPublicProfile =
        DonorPublicProfile.create(
            targetProfile,
            targetChain,
            donor,
            ProfileEndpoint.create(profileBytes(4, 1), 42_321),
        )
}

internal data class PublicProfileTestIdentity(
    val keyPair: KeyPair,
    val certificate: X509Certificate,
)

private class PublicProfileTestPki {
    private var serial = 1L
    private val now = Instant.now()

    fun root(name: String): PublicProfileTestIdentity {
        val keys = keyPair()
        val subject = X500Name("CN=$name")
        return PublicProfileTestIdentity(keys, certificate(subject, subject, keys, keys, true))
    }

    fun leaf(name: String, issuer: PublicProfileTestIdentity): PublicProfileTestIdentity {
        val keys = keyPair()
        return PublicProfileTestIdentity(
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

    private fun certificate(
        issuer: X500Name,
        subject: X500Name,
        subjectKeys: KeyPair,
        issuerKeys: KeyPair,
        isCa: Boolean,
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
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer)).also {
            it.verify(issuerKeys.public)
        }
    }

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
}

internal fun profileBytes(size: Int, seed: Int): ByteArray =
    ByteArray(size) { index -> (index + seed).toByte() }
