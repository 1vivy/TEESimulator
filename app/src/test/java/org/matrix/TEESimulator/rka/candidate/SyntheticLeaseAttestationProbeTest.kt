package org.matrix.TEESimulator.rka.candidate

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.attestation.ATTESTATION_OID

class SyntheticLeaseAttestationProbeTest {
    @Test
    fun verifiesBoundChallengeAndPersistedLeaseIssuer() {
        val fixture = fixture()

        val receipt =
            SyntheticLeaseAttestationVerifier.verify(
                fixture.leafKey.public,
                fixture.chain,
                fixture.challenge,
                sha256(fixture.chain[1].encoded),
                fixture.nowMillis,
            )

        assertEquals(3, receipt.chainCount)
        assertEquals(2, receipt.edgeCount)
    }

    @Test
    fun rejectsDifferentChallengeOrIssuer() {
        val fixture = fixture()

        assertTrue(
            runCatching {
                    SyntheticLeaseAttestationVerifier.verify(
                        fixture.leafKey.public,
                        fixture.chain,
                        fixture.challenge.copyOf().also { it[0] = it[0].inc() },
                        sha256(fixture.chain[1].encoded),
                        fixture.nowMillis,
                    )
                }
                .isFailure
        )
        assertTrue(
            runCatching {
                    SyntheticLeaseAttestationVerifier.verify(
                        fixture.leafKey.public,
                        fixture.chain,
                        fixture.challenge,
                        ByteArray(32),
                        fixture.nowMillis,
                    )
                }
                .isFailure
        )
    }

    private fun fixture(): Fixture {
        val now = Instant.now()
        val notBefore = Date.from(now.minusSeconds(60))
        val notAfter = Date.from(now.plusSeconds(3_600))
        val rootKey = ecKey()
        val issuerKey = ecKey()
        val leafKey = ecKey()
        val root = certificate("CN=Root", "CN=Root", rootKey, rootKey, 1, notBefore, notAfter, true)
        val issuer =
            certificate(
                "CN=Lease Issuer",
                "CN=Root",
                issuerKey,
                rootKey,
                2,
                notBefore,
                notAfter,
                true,
            )
        val challenge = ByteArray(32) { it.toByte() }
        val leaf =
            certificate(
                "CN=Generated Key",
                "CN=Lease Issuer",
                leafKey,
                issuerKey,
                3,
                notBefore,
                notAfter,
                false,
                challenge,
            )
        return Fixture(now.toEpochMilli(), challenge, leafKey, listOf(leaf, issuer, root))
    }

    private fun certificate(
        subject: String,
        issuer: String,
        publicKey: KeyPair,
        signer: KeyPair,
        serial: Long,
        notBefore: Date,
        notAfter: Date,
        isCa: Boolean,
        challenge: ByteArray? = null,
    ) =
        JcaX509CertificateConverter()
            .getCertificate(
                JcaX509v3CertificateBuilder(
                        X500Name(issuer),
                        BigInteger.valueOf(serial),
                        notBefore,
                        notAfter,
                        X500Name(subject),
                        publicKey.public,
                    )
                    .apply {
                        addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
                        if (isCa) {
                            addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
                        }
                        if (challenge != null) {
                            addExtension(ATTESTATION_OID, false, keyDescription(challenge))
                        }
                    }
                    .build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private))
            )

    private fun keyDescription(challenge: ByteArray) =
        DERSequence(
            arrayOf(
                ASN1Integer(400),
                ASN1Enumerated(1),
                ASN1Integer(400),
                ASN1Enumerated(1),
                DEROctetString(challenge),
                DEROctetString(byteArrayOf()),
                DERSequence(),
                DERSequence(),
            )
        )

    private fun ecKey(): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private data class Fixture(
        val nowMillis: Long,
        val challenge: ByteArray,
        val leafKey: KeyPair,
        val chain: List<java.security.cert.X509Certificate>,
    )
}
