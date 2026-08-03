package org.matrix.TEESimulator.rka.candidate

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SyntheticLeaseCodecTest {
    @Test
    fun decodesCurrentLeaseAndProvesPrivateKeyMatchesCertifiedLeaf() {
        val fixture = fixture()

        val decoded = SyntheticLeaseCodec.decodeCurrent(fixture.encoded, fixture.nowMillis)

        assertEquals(0, decoded.epoch)
        assertEquals(fixture.notAfterMillis, decoded.validUntilMillis)
        assertEquals(2, decoded.keyBox.certificates.size)
        assertArrayEquals(fixture.leaf.publicKey.encoded, decoded.keyBox.keyPair.public.encoded)
        val input = "candidate offline signing proof".toByteArray()
        val signed =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(decoded.keyBox.keyPair.private)
                update(input)
                sign()
            }
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(fixture.leaf.publicKey)
                update(input)
                verify(signed)
            }
        )
    }

    @Test
    fun rejectsTamperedRecord() {
        val fixture = fixture()
        fixture.encoded[fixture.encoded.lastIndex] = fixture.encoded.last().inc()

        assertTrue(
            runCatching { SyntheticLeaseCodec.decodeCurrent(fixture.encoded, fixture.nowMillis) }
                .isFailure
        )
    }

    @Test
    fun rejectsExpiredRecord() {
        val fixture = fixture()

        assertTrue(
            runCatching {
                    SyntheticLeaseCodec.decodeCurrent(fixture.encoded, fixture.notAfterMillis)
                }
                .isFailure
        )
    }

    @Test
    fun bindsLeaseToCurrentPairedActivation() {
        val fixture = fixture()
        val activation = ByteArray(237)
        byteArrayOf(
                'R'.code.toByte(),
                'K'.code.toByte(),
                'P'.code.toByte(),
                'A'.code.toByte(),
                1,
            )
            .copyInto(activation)
        fixture.peer.copyInto(activation, 5)
        fixture.profile.copyInto(activation, 37)

        SyntheticLeaseActivationCodec.requireMatch(
            activation,
            fixture.profile,
            fixture.peer,
        )
        activation[5] = activation[5].inc()
        assertTrue(
            runCatching {
                    SyntheticLeaseActivationCodec.requireMatch(
                        activation,
                        fixture.profile,
                        fixture.peer,
                    )
                }
                .isFailure
        )
    }

    private fun fixture(): LeaseFixture {
        val now = Instant.now()
        val nowMillis = now.toEpochMilli()
        val notBeforeMillis = now.minusSeconds(60).epochSecond * 1_000
        val notAfterMillis = now.plusSeconds(3_600).epochSecond * 1_000
        val rootKey = ecKey()
        val leafKey = ecKey()
        val root =
            certificate(
                subject = "CN=Synthetic Lease Root",
                issuer = "CN=Synthetic Lease Root",
                publicKey = rootKey,
                signer = rootKey,
                serial = 1,
                notBeforeMillis,
                notAfterMillis,
                isCa = true,
            )
        val leaf =
            certificate(
                subject = "CN=Synthetic Lease Attestation Key",
                issuer = "CN=Synthetic Lease Root",
                publicKey = leafKey,
                signer = rootKey,
                serial = 2,
                notBeforeMillis,
                notAfterMillis,
                isCa = true,
            )
        val profile = ByteArray(32) { 0x31 }
        val peer = ByteArray(32) { 0x42 }
        val chain = listOf(leaf.encoded, root.encoded)
        val leaseId =
            leaseId(
                0,
                profile,
                peer,
                notBeforeMillis,
                notAfterMillis,
                leafKey.public.encoded,
                chain,
            )
        val encoded =
            ByteArrayOutputStream()
                .also { bytes ->
                    DataOutputStream(bytes).use { output ->
                        output.write(
                            byteArrayOf(
                                'R'.code.toByte(),
                                'K'.code.toByte(),
                                'S'.code.toByte(),
                                'L'.code.toByte(),
                                1,
                            )
                        )
                        output.writeByte(1)
                        output.writeByte(0)
                        output.writeLong(0)
                        output.write(profile)
                        output.write(peer)
                        output.writeLong(notBeforeMillis)
                        output.writeLong(notAfterMillis)
                        output.write(leaseId)
                        output.writeShort(leafKey.private.encoded.size)
                        output.write(leafKey.private.encoded)
                        output.writeShort(leafKey.public.encoded.size)
                        output.write(leafKey.public.encoded)
                        output.writeByte(chain.size)
                        chain.forEach {
                            output.writeInt(it.size)
                            output.write(it)
                        }
                    }
                }
                .toByteArray()
        return LeaseFixture(encoded, nowMillis, notAfterMillis, leaf, profile, peer)
    }

    private fun ecKey(): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    private fun certificate(
        subject: String,
        issuer: String,
        publicKey: KeyPair,
        signer: KeyPair,
        serial: Long,
        notBeforeMillis: Long,
        notAfterMillis: Long,
        isCa: Boolean,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name(issuer),
                BigInteger.valueOf(serial),
                Date(notBeforeMillis),
                Date(notAfterMillis),
                X500Name(subject),
                publicKey.public,
            )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        return JcaX509CertificateConverter()
            .getCertificate(
                builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private))
            )
    }

    private fun leaseId(
        epoch: Long,
        profile: ByteArray,
        peer: ByteArray,
        notBeforeMillis: Long,
        notAfterMillis: Long,
        publicSpki: ByteArray,
        chain: List<ByteArray>,
    ): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update("TEESimulator-RS synthetic lease id v1\u0000".toByteArray())
            update(longBytes(epoch))
            update(profile)
            update(peer)
            update(longBytes(notBeforeMillis))
            update(longBytes(notAfterMillis))
            update(longBytes(publicSpki.size.toLong()))
            update(publicSpki)
            chain.forEach {
                update(longBytes(it.size.toLong()))
                update(it)
            }
            digest()
        }

    private fun longBytes(value: Long): ByteArray =
        ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array()
}

private data class LeaseFixture(
    val encoded: ByteArray,
    val nowMillis: Long,
    val notAfterMillis: Long,
    val leaf: X509Certificate,
    val profile: ByteArray,
    val peer: ByteArray,
)
