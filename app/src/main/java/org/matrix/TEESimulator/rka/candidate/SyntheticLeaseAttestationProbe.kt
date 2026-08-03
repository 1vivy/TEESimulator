package org.matrix.TEESimulator.rka.candidate

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.system.exitProcess
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.cert.X509CertificateHolder
import org.matrix.TEESimulator.App
import org.matrix.TEESimulator.attestation.ATTESTATION_OID
import org.matrix.TEESimulator.attestation.AttestationConstants

/**
 * Root/app-UID diagnostic for proving that a persisted synthetic lease serves a real Android
 * Keystore attestation request. The root mode reveals only the expected issuer certificate digest;
 * the probe mode runs as the selected application UID and never reads the root-owned lease file.
 */
object SyntheticLeaseAttestationProbe {
    private const val ROOT_DIGEST_COMMAND = "lease-issuer-sha256"
    private const val EXPECTED_DIGEST_PREFIX = "--expected-lease-issuer-sha256="
    private const val ALIAS_PREFIX = "teesimulator_rka_attestation_probe_"

    @JvmStatic
    fun main(args: Array<String>) {
        var stage = "INPUT"
        try {
            if (args.contentEquals(arrayOf(ROOT_DIGEST_COMMAND))) {
                val issuer = SyntheticLeaseRegistry.current().keyBox.certificates.first()
                println("lease_issuer_sha256=${sha256(issuer.encoded).toHex()}")
                return
            }

            require(args.size == 1 && args[0].startsWith(EXPECTED_DIGEST_PREFIX))
            val expectedIssuerDigest =
                decodeHex(args[0].removePrefix(EXPECTED_DIGEST_PREFIX), SHA256_BYTES)
            val random = SecureRandom()
            val challenge = ByteArray(CHALLENGE_BYTES).also(random::nextBytes)
            val alias = ALIAS_PREFIX + ByteArray(ALIAS_SUFFIX_BYTES).also(random::nextBytes).toHex()
            stage = "RUNTIME"
            App.prepareEnvironment()
            stage = "PROVIDER"
            android.security.keystore2.AndroidKeyStoreProvider.install()
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            var generated = false
            try {
                stage = "GENERATE"
                val generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
                generator.initialize(
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .build()
                )
                val keyPair = generator.generateKeyPair()
                generated = true

                stage = "CHAIN"
                val certificates =
                    requireNotNull(keyStore.getCertificateChain(alias)).map {
                        it as X509Certificate
                    }
                val receipt =
                    SyntheticLeaseAttestationVerifier.verify(
                        keyPair.public,
                        certificates,
                        challenge,
                        expectedIssuerDigest,
                        System.currentTimeMillis(),
                    )

                stage = "SIGN"
                val proof = ByteArray(PROOF_BYTES).also(random::nextBytes)
                val signature =
                    Signature.getInstance("SHA256withECDSA").run {
                        initSign(keyPair.private)
                        update(proof)
                        sign()
                    }
                require(
                    Signature.getInstance("SHA256withECDSA").run {
                        initVerify(keyPair.public)
                        update(proof)
                        verify(signature)
                    }
                )

                stage = "CLEANUP"
                keyStore.deleteEntry(alias)
                generated = false
                println(
                    "synthetic_lease_attestation_status=READY " +
                        "chain_count=${receipt.chainCount} " +
                        "edge_count=${receipt.edgeCount} " +
                        "challenge=BOUND root_self_signed=true issuer_match=true signing=READY"
                )
            } finally {
                if (generated || keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            }
        } catch (error: Throwable) {
            System.err.println(
                "synthetic_lease_attestation_status=FAILED " +
                    "stage=$stage type=${error.javaClass.simpleName}"
            )
            exitProcess(1)
        }
    }

    private fun decodeHex(value: String, expectedBytes: Int): ByteArray {
        require(value.length == expectedBytes * 2)
        return ByteArray(expectedBytes) { index ->
            val offset = index * 2
            value.substring(offset, offset + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

internal data class SyntheticLeaseAttestationReceipt(val chainCount: Int, val edgeCount: Int)

/** Pure verifier kept separate from Android Keystore I/O so the receipt contract is unit-tested. */
internal object SyntheticLeaseAttestationVerifier {
    fun verify(
        generatedPublicKey: PublicKey,
        certificates: List<X509Certificate>,
        challenge: ByteArray,
        expectedIssuerDigest: ByteArray,
        nowMillis: Long,
    ): SyntheticLeaseAttestationReceipt {
        require(certificates.size >= MIN_CHAIN_CERTIFICATES)
        require(challenge.isNotEmpty())
        require(expectedIssuerDigest.size == SHA256_BYTES)
        val leaf = certificates.first()
        require(leaf.publicKey.encoded.contentEquals(generatedPublicKey.encoded))
        require(attestationChallenge(leaf).contentEquals(challenge))
        require(sha256(certificates[1].encoded).contentEquals(expectedIssuerDigest))
        require(certificates[1].basicConstraints >= 0)
        require(certificates[1].keyUsage?.getOrNull(KEY_CERT_SIGN_INDEX) == true)

        val now = Date(nowMillis)
        certificates.forEach { it.checkValidity(now) }
        certificates.zipWithNext().forEach { (child, issuer) ->
            require(child.issuerX500Principal == issuer.subjectX500Principal)
            child.verify(issuer.publicKey)
        }
        val root = certificates.last()
        require(root.issuerX500Principal == root.subjectX500Principal)
        root.verify(root.publicKey)
        return SyntheticLeaseAttestationReceipt(certificates.size, certificates.size - 1)
    }

    private fun attestationChallenge(certificate: X509Certificate): ByteArray {
        val extension =
            requireNotNull(X509CertificateHolder(certificate.encoded).getExtension(ATTESTATION_OID))
        val fields = ASN1Sequence.getInstance(extension.extnValue.octets).toArray()
        require(fields.size > AttestationConstants.KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX)
        return ASN1OctetString.getInstance(
                fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX]
            )
            .octets
    }
}

private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

private const val SHA256_BYTES = 32
private const val CHALLENGE_BYTES = 32
private const val PROOF_BYTES = 32
private const val ALIAS_SUFFIX_BYTES = 8
private const val MIN_CHAIN_CERTIFICATES = 3
private const val KEY_CERT_SIGN_INDEX = 5
