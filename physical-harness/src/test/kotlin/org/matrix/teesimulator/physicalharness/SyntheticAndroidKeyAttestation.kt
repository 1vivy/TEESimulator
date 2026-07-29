package org.matrix.teesimulator.physicalharness

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal enum class AuthorizationListLocation {
    SOFTWARE,
    TEE,
}

internal data class SyntheticApplicationId(
    val bytes: ByteArray,
    val location: AuthorizationListLocation = AuthorizationListLocation.SOFTWARE,
    val explicit: Boolean = true,
)

internal object SyntheticAndroidKeyAttestation {
    private val extensionOid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

    fun material(
        challenge: ByteArray,
        applicationId: ByteArray,
        backendSecurityLevel: BackendSecurityLevel = BackendSecurityLevel.TRUSTED_ENVIRONMENT,
        attestationSecurityLevel: Int = TRUSTED_ENVIRONMENT,
        keymasterSecurityLevel: Int = TRUSTED_ENVIRONMENT,
        applicationIds: List<SyntheticApplicationId> =
            listOf(SyntheticApplicationId(applicationId)),
        extensionPublicKeyMatches: Boolean = true,
        includeGeneratedKeyCertificate: Boolean = true,
    ): BackendKeyMaterial {
        val generatedKeyPair = keyPair()
        val extensionKeyPair = if (extensionPublicKeyMatches) generatedKeyPair else keyPair()
        val extensionCertificate =
            certificate(
                extensionKeyPair,
                keyDescription(
                    challenge,
                    attestationSecurityLevel,
                    keymasterSecurityLevel,
                    applicationIds,
                ),
            )
        val chain = mutableListOf(extensionCertificate)
        if (!extensionPublicKeyMatches && includeGeneratedKeyCertificate) {
            chain += certificate(generatedKeyPair, keyDescription = null)
        }

        return BackendKeyMaterial(backendSecurityLevel, generatedKeyPair.public.encoded, chain)
    }

    private fun keyDescription(
        challenge: ByteArray,
        attestationSecurityLevel: Int,
        keymasterSecurityLevel: Int,
        applicationIds: List<SyntheticApplicationId>,
    ) =
        DERSequence(
            arrayOf(
                ASN1Integer(4),
                ASN1Enumerated(attestationSecurityLevel),
                ASN1Integer(41),
                ASN1Enumerated(keymasterSecurityLevel),
                DEROctetString(challenge),
                DEROctetString(byteArrayOf()),
                authorizationList(applicationIds, AuthorizationListLocation.SOFTWARE),
                authorizationList(applicationIds, AuthorizationListLocation.TEE),
            )
        )

    private fun authorizationList(
        applicationIds: List<SyntheticApplicationId>,
        location: AuthorizationListLocation,
    ): DERSequence =
        DERSequence(
            applicationIds
                .filter { it.location == location }
                .map<SyntheticApplicationId, ASN1Encodable> {
                    DERTaggedObject(it.explicit, APPLICATION_ID_TAG, DEROctetString(it.bytes))
                }
                .toTypedArray()
        )

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

    private fun certificate(keyPair: KeyPair, keyDescription: DERSequence?): ByteArray {
        val subject = X500Name("CN=Synthetic Android Key")
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val builder =
            JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)),
                subject,
                keyPair.public,
            )
        if (keyDescription != null) {
            builder.addExtension(extensionOid, false, keyDescription)
        }
        return builder
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
            .encoded
    }

    private const val TRUSTED_ENVIRONMENT = 1
    private const val APPLICATION_ID_TAG = 709
}
