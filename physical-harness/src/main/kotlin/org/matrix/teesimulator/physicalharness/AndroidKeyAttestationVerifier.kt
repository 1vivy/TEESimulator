package org.matrix.teesimulator.physicalharness

import java.io.IOException
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder

internal class VerifiedAndroidKey(
    challenge: ByteArray,
    publicKey: ByteArray,
    certificateChain: List<ByteArray>,
) {
    private val challengeBytes = challenge.copyOf()
    private val publicKeyBytes = publicKey.copyOf()
    private val certificateBytes = certificateChain.map(ByteArray::copyOf)

    val challenge: ByteArray
        get() = challengeBytes.copyOf()

    val publicKey: ByteArray
        get() = publicKeyBytes.copyOf()

    val certificateChain: List<ByteArray>
        get() = certificateBytes.map(ByteArray::copyOf)
}

internal object AndroidKeyAttestationVerifier {
    private val extensionOid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    private val ecPublicKeyOid = ASN1ObjectIdentifier("1.2.840.10045.2.1")
    private val p256CurveOid = ASN1ObjectIdentifier("1.2.840.10045.3.1.7")

    fun verify(
        material: BackendKeyMaterial,
        identity: CanonicalCallerIdentity,
        expectedChallenge: ByteArray?,
    ): VerifiedAndroidKey {
        if (material.securityLevel != BackendSecurityLevel.TRUSTED_ENVIRONMENT) {
            reject("KeyInfo security level is not trusted environment")
        }
        val generatedPublicKey = material.generatedPublicKey
        val certificateChain = material.certificateChain
        if (generatedPublicKey.isEmpty() || certificateChain.isEmpty()) {
            reject("Key metadata is incomplete")
        }

        val generatedKeyInfo = parsePublicKey(generatedPublicKey)
        requireP256(generatedKeyInfo)
        val certificateHolders = certificateChain.map(::parseCertificate)
        val matchingCertificates =
            certificateHolders.filter { certificate ->
                certificate.getExtension(extensionOid) != null &&
                    MessageDigest.isEqual(
                        certificate.subjectPublicKeyInfo.encoded,
                        generatedPublicKey,
                    )
            }
        if (matchingCertificates.size != 1) {
            reject("Attestation extension is not uniquely bound to the generated key")
        }

        val attestedCertificate = matchingCertificates.single()
        requireP256(attestedCertificate.subjectPublicKeyInfo)
        val keyDescription = parseKeyDescription(attestedCertificate)
        requireTrustedEnvironment(keyDescription, ATTESTATION_SECURITY_LEVEL_INDEX)
        requireTrustedEnvironment(keyDescription, KEYMASTER_SECURITY_LEVEL_INDEX)
        val challenge = octetsAt(keyDescription, CHALLENGE_INDEX, "attestation challenge")
        if (
            challenge.isEmpty() ||
                challenge.size > AndroidKeystoreDonor.MAX_ATTESTATION_CHALLENGE_BYTES
        ) {
            reject("Attestation challenge is outside accepted bounds")
        }
        if (expectedChallenge != null && !MessageDigest.isEqual(challenge, expectedChallenge)) {
            reject("Attestation challenge does not match the request")
        }

        val applicationIds =
            listOf(SOFTWARE_ENFORCED_INDEX, TEE_ENFORCED_INDEX).flatMap { index ->
                applicationIdTags(sequenceAt(keyDescription, index))
            }
        if (applicationIds.size != 1) {
            reject("Attestation application ID tag is not unique")
        }
        val applicationIdTag = applicationIds.single()
        if (!applicationIdTag.isExplicit) {
            reject("Attestation application ID tag is not explicit")
        }
        val attestedApplicationId =
            try {
                ASN1OctetString.getInstance(applicationIdTag.explicitBaseObject).octets
            } catch (exception: IllegalArgumentException) {
                reject("Attestation application ID is malformed", exception)
            }
        if (!MessageDigest.isEqual(attestedApplicationId, identity.attestationApplicationIdDer)) {
            reject("Attestation application ID does not match the caller")
        }

        val attestedPublicKey = attestedCertificate.subjectPublicKeyInfo.encoded
        if (!MessageDigest.isEqual(attestedPublicKey, generatedPublicKey)) {
            reject("Metadata public key does not match the attested certificate")
        }
        return VerifiedAndroidKey(challenge, attestedPublicKey, certificateChain)
    }

    private fun parsePublicKey(encoded: ByteArray): SubjectPublicKeyInfo =
        try {
            SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encoded))
        } catch (exception: IOException) {
            reject("Generated public key is malformed", exception)
        } catch (exception: IllegalArgumentException) {
            reject("Generated public key is malformed", exception)
        }

    private fun parseCertificate(encoded: ByteArray): X509CertificateHolder =
        try {
            X509CertificateHolder(encoded)
        } catch (exception: IOException) {
            reject("Certificate chain is malformed", exception)
        }

    private fun parseKeyDescription(certificate: X509CertificateHolder): ASN1Sequence {
        val encoded = certificate.getExtension(extensionOid).extnValue.octets
        val primitive =
            try {
                ASN1Primitive.fromByteArray(encoded)
            } catch (exception: IOException) {
                reject("KeyDescription is malformed", exception)
            }
        val sequence =
            try {
                ASN1Sequence.getInstance(primitive)
            } catch (exception: IllegalArgumentException) {
                reject("KeyDescription is malformed", exception)
            }
        if (sequence.size() < REQUIRED_KEY_DESCRIPTION_SIZE) {
            reject("KeyDescription is incomplete")
        }
        return sequence
    }

    private fun requireP256(publicKey: SubjectPublicKeyInfo) {
        val algorithm = publicKey.algorithm
        val curve = algorithm.parameters?.toASN1Primitive()
        if (algorithm.algorithm != ecPublicKeyOid || curve != p256CurveOid) {
            reject("Attested key is not EC P-256")
        }
    }

    private fun requireTrustedEnvironment(description: ASN1Sequence, index: Int) {
        val securityLevel =
            try {
                ASN1Enumerated.getInstance(description.getObjectAt(index))
            } catch (exception: IllegalArgumentException) {
                reject("KeyDescription security level is malformed", exception)
            }
        if (!securityLevel.hasValue(TRUSTED_ENVIRONMENT)) {
            reject("KeyDescription security level is not trusted environment")
        }
    }

    private fun octetsAt(description: ASN1Sequence, index: Int, field: String): ByteArray =
        try {
            ASN1OctetString.getInstance(description.getObjectAt(index)).octets
        } catch (exception: IllegalArgumentException) {
            reject("KeyDescription $field is malformed", exception)
        }

    private fun sequenceAt(description: ASN1Sequence, index: Int): ASN1Sequence =
        try {
            ASN1Sequence.getInstance(description.getObjectAt(index))
        } catch (exception: IllegalArgumentException) {
            reject("KeyDescription authorization list is malformed", exception)
        }

    private fun applicationIdTags(authorizationList: ASN1Sequence): List<ASN1TaggedObject> =
        authorizationList
            .map { element ->
                try {
                    ASN1TaggedObject.getInstance(element)
                } catch (exception: IllegalArgumentException) {
                    reject("KeyDescription authorization is malformed", exception)
                }
            }
            .filter { it.hasContextTag(APPLICATION_ID_TAG) }

    private fun reject(message: String, cause: Throwable? = null): Nothing {
        throw AndroidKeystoreDonorException.AttestationRejected(message, cause)
    }

    private const val TRUSTED_ENVIRONMENT = 1
    private const val ATTESTATION_SECURITY_LEVEL_INDEX = 1
    private const val KEYMASTER_SECURITY_LEVEL_INDEX = 3
    private const val CHALLENGE_INDEX = 4
    private const val SOFTWARE_ENFORCED_INDEX = 6
    private const val TEE_ENFORCED_INDEX = 7
    private const val REQUIRED_KEY_DESCRIPTION_SIZE = 8
    private const val APPLICATION_ID_TAG = 709
}
