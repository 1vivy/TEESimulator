package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.Key
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.Collections
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.matrix.teesimulator.twophone.SpkiPin

sealed class DonorTlsServerIdentityException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class AliasAlreadyExists :
        DonorTlsServerIdentityException("donor TLS server identity already exists")

    class IdentityNotFound : DonorTlsServerIdentityException("donor TLS server identity not found")

    class InvalidKey(cause: Throwable? = null) :
        DonorTlsServerIdentityException("invalid donor TLS server key", cause)

    class InvalidCertificate(cause: Throwable? = null) :
        DonorTlsServerIdentityException("invalid donor TLS server certificate", cause)

    class UntrustedSecurityLevel :
        DonorTlsServerIdentityException("untrusted donor TLS server security level")

    class PinMismatch : DonorTlsServerIdentityException("donor TLS server pin mismatch")

    class ProbeFailure(cause: Throwable? = null) :
        DonorTlsServerIdentityException("donor TLS server signature probe failed", cause)

    class BackendFailure(cause: Throwable) :
        DonorTlsServerIdentityException("AndroidKeyStore donor TLS operation failed", cause)
}

class ProvisionedDonorTlsServerPublicMaterial
internal constructor(
    val alias: String,
    leafCertificateDer: ByteArray,
    certificateChainDer: List<ByteArray>,
    val pin: SpkiPin,
) {
    private val stableLeafCertificateDer = leafCertificateDer.copyOf()
    private val stableCertificateChainDer = certificateChainDer.map(ByteArray::copyOf)

    val leafCertificateDer: ByteArray
        get() = stableLeafCertificateDer.copyOf()

    val certificateChainDer: List<ByteArray>
        get() = stableCertificateChainDer.map(ByteArray::copyOf)
}

class OpenedDonorTlsServerIdentity
internal constructor(
    val alias: String,
    val keyStore: KeyStore,
    keyPassword: CharArray?,
    certificateChainDer: List<ByteArray>,
    val pin: SpkiPin,
) {
    private val stableKeyPassword = keyPassword?.copyOf()
    private val stableCertificateChainDer = certificateChainDer.map(ByteArray::copyOf)

    val keyPassword: CharArray?
        get() = stableKeyPassword?.copyOf()

    val certificateChainDer: List<ByteArray>
        get() = stableCertificateChainDer.map(ByteArray::copyOf)
}

internal enum class DonorTlsServerKeyPurpose {
    SIGN
}

internal class DonorTlsServerGenerationSpec(
    purposes: Set<DonorTlsServerKeyPurpose>,
    val curve: String,
    val digest: String,
    val userAuthenticationRequired: Boolean,
    val strongBoxBacked: Boolean,
    attestationChallenge: ByteArray?,
    val certificateSubject: X500Principal,
    val certificateSerialNumber: BigInteger,
    certificateNotBefore: Date,
    certificateNotAfter: Date,
) {
    val purposes: Set<DonorTlsServerKeyPurpose> = Collections.unmodifiableSet(purposes.toSet())
    private val stableAttestationChallenge = attestationChallenge?.copyOf()
    private val stableCertificateNotBefore = Date(certificateNotBefore.time)
    private val stableCertificateNotAfter = Date(certificateNotAfter.time)

    val attestationChallenge: ByteArray?
        get() = stableAttestationChallenge?.copyOf()

    val certificateNotBefore: Date
        get() = Date(stableCertificateNotBefore.time)

    val certificateNotAfter: Date
        get() = Date(stableCertificateNotAfter.time)
}

internal class DonorTlsServerBackendMaterial(
    val key: Key?,
    val securityLevel: BackendSecurityLevel,
    certificateChain: List<Certificate>,
    val keyStore: KeyStore,
    keyPassword: CharArray?,
) {
    val certificateChain: List<Certificate> = certificateChain.toList()
    private val stableKeyPassword = keyPassword?.copyOf()

    val keyPassword: CharArray?
        get() = stableKeyPassword?.copyOf()
}

internal interface DonorTlsServerIdentityBackend {
    fun containsAlias(alias: String): Boolean

    fun generate(alias: String, spec: DonorTlsServerGenerationSpec)

    fun load(alias: String): DonorTlsServerBackendMaterial?

    fun signProbe(privateKey: PrivateKey, input: ByteArray): ByteArray

    fun verifyProbe(publicKey: PublicKey, input: ByteArray, signature: ByteArray): Boolean

    fun delete(alias: String)
}

object AndroidKeyStoreDonorTlsServerIdentity {
    const val KEY_ALIAS = "teesim_donor_tls_server_v1"

    fun provisionNew(
        now: Instant,
        secureRandom: SecureRandom,
    ): ProvisionedDonorTlsServerPublicMaterial =
        provisionNew(now, secureRandom, PlatformDonorTlsServerIdentityBackend())

    internal fun provisionNew(
        now: Instant,
        secureRandom: SecureRandom,
        backend: DonorTlsServerIdentityBackend,
    ): ProvisionedDonorTlsServerPublicMaterial =
        synchronized(identityMutationLock) {
            if (backendCall { backend.containsAlias(KEY_ALIAS) }) {
                throw DonorTlsServerIdentityException.AliasAlreadyExists()
            }
            val spec = generationSpec(now, secureRandom)
            backendCall { backend.generate(KEY_ALIAS, spec) }
            try {
                val validated = loadValidated(backend, now, expectedPin = null)
                ProvisionedDonorTlsServerPublicMaterial(
                    KEY_ALIAS,
                    validated.certificateChainDer.first(),
                    validated.certificateChainDer,
                    validated.pin,
                )
            } catch (failure: RuntimeException) {
                cleanupRejectedGeneration(backend, failure)
            }
        }

    fun openExisting(expectedPin: SpkiPin, now: Instant): OpenedDonorTlsServerIdentity =
        openExisting(expectedPin, now, PlatformDonorTlsServerIdentityBackend())

    internal fun openExisting(
        expectedPin: SpkiPin,
        now: Instant,
        backend: DonorTlsServerIdentityBackend,
    ): OpenedDonorTlsServerIdentity =
        synchronized(identityMutationLock) {
            if (!backendCall { backend.containsAlias(KEY_ALIAS) }) {
                throw DonorTlsServerIdentityException.IdentityNotFound()
            }
            val validated = loadValidated(backend, now, expectedPin)
            OpenedDonorTlsServerIdentity(
                KEY_ALIAS,
                validated.material.keyStore,
                validated.material.keyPassword,
                validated.certificateChainDer,
                validated.pin,
            )
        }

    private fun generationSpec(
        now: Instant,
        secureRandom: SecureRandom,
    ): DonorTlsServerGenerationSpec =
        DonorTlsServerGenerationSpec(
            purposes = setOf(DonorTlsServerKeyPurpose.SIGN),
            curve = P256_CURVE,
            digest = SHA256_DIGEST,
            userAuthenticationRequired = false,
            strongBoxBacked = false,
            attestationChallenge = null,
            certificateSubject = CERTIFICATE_SUBJECT,
            certificateSerialNumber = randomSerial(secureRandom),
            certificateNotBefore = Date.from(now.minus(1, ChronoUnit.DAYS)),
            certificateNotAfter = Date.from(now.atZone(ZoneOffset.UTC).plusYears(20).toInstant()),
        )

    private fun randomSerial(secureRandom: SecureRandom): BigInteger {
        val bytes = ByteArray(SERIAL_BYTES)
        do {
            secureRandom.nextBytes(bytes)
        } while (bytes.all { it == 0.toByte() })
        return BigInteger(1, bytes)
    }

    private fun loadValidated(
        backend: DonorTlsServerIdentityBackend,
        now: Instant,
        expectedPin: SpkiPin?,
    ): ValidatedIdentity {
        val material =
            backendCall { backend.load(KEY_ALIAS) }
                ?: throw DonorTlsServerIdentityException.IdentityNotFound()
        val privateKey = material.key as? PrivateKey ?: invalidKey()
        if (!privateKey.algorithm.equals("EC", ignoreCase = true) || privateKey.encoded != null) {
            invalidKey()
        }
        if (material.securityLevel != BackendSecurityLevel.TRUSTED_ENVIRONMENT) {
            throw DonorTlsServerIdentityException.UntrustedSecurityLevel()
        }

        val certificates = validatedCertificates(material.certificateChain)
        val leaf = certificates.first().certificate
        validateLeaf(leaf, now)
        runProbe(backend, privateKey, leaf.publicKey)
        val pin = certificatePin(leaf)
        if (expectedPin != null && !MessageDigest.isEqual(pin.digest, expectedPin.digest)) {
            throw DonorTlsServerIdentityException.PinMismatch()
        }
        return ValidatedIdentity(material, certificates.map(ParsedCertificate::der), pin)
    }

    private fun validatedCertificates(chain: List<Certificate>): List<ParsedCertificate> {
        if (chain.isEmpty() || chain.any { it !is X509Certificate }) invalidCertificate()
        return try {
            chain.map { certificate ->
                val der = certificate.encoded?.copyOf() ?: invalidCertificate()
                if (der.isEmpty()) invalidCertificate()
                val input = ByteArrayInputStream(der)
                val parsed =
                    CertificateFactory.getInstance("X.509").generateCertificate(input)
                        as? X509Certificate ?: invalidCertificate()
                if (input.available() != 0 || !MessageDigest.isEqual(der, parsed.encoded)) {
                    invalidCertificate()
                }
                ParsedCertificate(parsed, der)
            }
        } catch (failure: DonorTlsServerIdentityException.InvalidCertificate) {
            throw failure
        } catch (failure: Exception) {
            throw DonorTlsServerIdentityException.InvalidCertificate(failure)
        }
    }

    private fun validateLeaf(leaf: X509Certificate, now: Instant) {
        try {
            leaf.checkValidity(Date.from(now))
            leaf.verify(leaf.publicKey)
            validateP256(leaf.publicKey)
        } catch (failure: DonorTlsServerIdentityException.InvalidCertificate) {
            throw failure
        } catch (failure: Exception) {
            throw DonorTlsServerIdentityException.InvalidCertificate(failure)
        }
    }

    private fun validateP256(publicKey: PublicKey) {
        if (!publicKey.algorithm.equals("EC", ignoreCase = true)) invalidCertificate()
        val ecKey = publicKey as? ECPublicKey ?: invalidCertificate()
        val actual = ecKey.params ?: invalidCertificate()
        val expected = p256Parameters()
        if (!sameParameters(actual, expected) || !pointIsOnCurve(ecKey, expected)) {
            invalidCertificate()
        }
        val encoded = publicKey.encoded
        if (encoded == null || encoded.isEmpty()) invalidCertificate()
    }

    private fun p256Parameters(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec(P256_CURVE))
            getParameterSpec(ECParameterSpec::class.java)
        }

    private fun sameParameters(actual: ECParameterSpec, expected: ECParameterSpec): Boolean {
        val actualField = actual.curve.field as? ECFieldFp ?: return false
        val expectedField = expected.curve.field as? ECFieldFp ?: return false
        return actualField.p == expectedField.p &&
            actual.curve.a == expected.curve.a &&
            actual.curve.b == expected.curve.b &&
            actual.generator == expected.generator &&
            actual.order == expected.order &&
            actual.cofactor == expected.cofactor
    }

    private fun pointIsOnCurve(key: ECPublicKey, parameters: ECParameterSpec): Boolean {
        val field = parameters.curve.field as? ECFieldFp ?: return false
        val x = key.w.affineX ?: return false
        val y = key.w.affineY ?: return false
        if (x.signum() < 0 || y.signum() < 0 || x >= field.p || y >= field.p) return false
        val left = y.modPow(BigInteger.TWO, field.p)
        val right =
            x.modPow(BigInteger.valueOf(3), field.p)
                .add(parameters.curve.a.multiply(x))
                .add(parameters.curve.b)
                .mod(field.p)
        return left == right
    }

    private fun runProbe(
        backend: DonorTlsServerIdentityBackend,
        privateKey: PrivateKey,
        publicKey: PublicKey,
    ) {
        val signature =
            try {
                backend.signProbe(privateKey, SIGNATURE_PROBE.copyOf()).copyOf()
            } catch (failure: Exception) {
                throw DonorTlsServerIdentityException.ProbeFailure(failure)
            }
        val verified =
            try {
                backend.verifyProbe(publicKey, SIGNATURE_PROBE.copyOf(), signature.copyOf())
            } catch (failure: Exception) {
                throw DonorTlsServerIdentityException.ProbeFailure(failure)
            }
        if (!verified) throw DonorTlsServerIdentityException.ProbeFailure()
    }

    private fun certificatePin(leaf: X509Certificate): SpkiPin =
        try {
            SpkiPin.from(leaf)
        } catch (failure: Exception) {
            throw DonorTlsServerIdentityException.InvalidCertificate(failure)
        }

    private fun cleanupRejectedGeneration(
        backend: DonorTlsServerIdentityBackend,
        failure: RuntimeException,
    ): Nothing {
        try {
            backendCall { backend.delete(KEY_ALIAS) }
        } catch (cleanupFailure: RuntimeException) {
            failure.addSuppressed(cleanupFailure)
        }
        throw failure
    }

    private fun invalidKey(): Nothing = throw DonorTlsServerIdentityException.InvalidKey()

    private fun invalidCertificate(): Nothing =
        throw DonorTlsServerIdentityException.InvalidCertificate()

    private inline fun <T> backendCall(block: () -> T): T =
        try {
            block()
        } catch (failure: DonorTlsServerIdentityException) {
            throw failure
        } catch (failure: Exception) {
            throw DonorTlsServerIdentityException.BackendFailure(failure)
        }

    private data class ParsedCertificate(val certificate: X509Certificate, val der: ByteArray)

    private data class ValidatedIdentity(
        val material: DonorTlsServerBackendMaterial,
        val certificateChainDer: List<ByteArray>,
        val pin: SpkiPin,
    )

    private const val P256_CURVE = "secp256r1"
    private const val SHA256_DIGEST = "SHA-256"
    private const val SERIAL_BYTES = 16
    private val CERTIFICATE_SUBJECT = X500Principal("CN=TEESimulator Donor TLS v1")
    private val SIGNATURE_PROBE =
        "TEESimulator\u0000donor-tls-server-identity\u0000v1".encodeToByteArray()
    private val identityMutationLock = Any()
}
