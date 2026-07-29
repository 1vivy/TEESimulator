package org.matrix.TEESimulator.twophone

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.matrix.teesimulator.twophone.SpkiPin

object AndroidKeyStoreTargetTlsClientIdentity {
    const val KEY_ALIAS = "teesim_target_tls_client_v1"

    fun provisionNew(
        now: Instant,
        secureRandom: SecureRandom,
    ): ProvisionedTargetTlsClientPublicMaterial =
        provisionNew(now, secureRandom, PlatformTargetTlsClientIdentityBackend())

    internal fun provisionNew(
        now: Instant,
        secureRandom: SecureRandom,
        backend: TargetTlsClientIdentityBackend,
    ): ProvisionedTargetTlsClientPublicMaterial =
        synchronized(identityMutationLock) {
            if (backendCall { backend.containsAlias(KEY_ALIAS) }) {
                throw TargetTlsClientIdentityException.AliasAlreadyExists()
            }
            backendCall { backend.generate(KEY_ALIAS, generationSpec(now, secureRandom)) }
            try {
                val identity = loadValidated(backend, now, expectedPin = null)
                ProvisionedTargetTlsClientPublicMaterial(
                    KEY_ALIAS,
                    identity.chain.first(),
                    identity.chain,
                    identity.pin,
                )
            } catch (failure: RuntimeException) {
                try {
                    backendCall { backend.delete(KEY_ALIAS) }
                } catch (cleanupFailure: RuntimeException) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }

    fun openExisting(expectedPin: SpkiPin, now: Instant): OpenedTargetTlsClientIdentity =
        openExisting(expectedPin, now, PlatformTargetTlsClientIdentityBackend())

    internal fun openExisting(
        expectedPin: SpkiPin,
        now: Instant,
        backend: TargetTlsClientIdentityBackend,
    ): OpenedTargetTlsClientIdentity =
        synchronized(identityMutationLock) {
            if (!backendCall { backend.containsAlias(KEY_ALIAS) }) {
                throw TargetTlsClientIdentityException.IdentityNotFound()
            }
            val identity = loadValidated(backend, now, expectedPin)
            OpenedTargetTlsClientIdentity(
                KEY_ALIAS,
                identity.material.keyStore,
                identity.material.keyPassword,
                identity.chain,
                identity.pin,
            )
        }

    private fun loadValidated(
        backend: TargetTlsClientIdentityBackend,
        now: Instant,
        expectedPin: SpkiPin?,
    ): ValidatedIdentity {
        val material =
            backendCall { backend.load(KEY_ALIAS) }
                ?: throw TargetTlsClientIdentityException.IdentityNotFound()
        val privateKey = material.key as? PrivateKey ?: invalidKey()
        if (
            material.ownerUid != ROOT_UID ||
                material.securityLevel != TargetTlsSecurityLevel.TRUSTED_ENVIRONMENT ||
                !privateKey.algorithm.equals("EC", ignoreCase = true) ||
                privateKey.encoded != null
        ) {
            invalidKey()
        }
        val certificates = validateCertificates(material.certificateChain)
        val leaf = certificates.first().certificate
        try {
            leaf.checkValidity(Date.from(now))
            requireP256(leaf)
        } catch (failure: TargetTlsClientIdentityException.InvalidCertificate) {
            throw failure
        } catch (failure: Exception) {
            throw TargetTlsClientIdentityException.InvalidCertificate(failure)
        }
        runProbe(backend, privateKey, leaf)
        val pin = SpkiPin.from(leaf)
        if (expectedPin != null && !MessageDigest.isEqual(pin.digest, expectedPin.digest)) {
            throw TargetTlsClientIdentityException.PinMismatch()
        }
        return ValidatedIdentity(material, certificates.map(ParsedCertificate::der), pin)
    }

    private fun validateCertificates(
        chain: List<java.security.cert.Certificate>
    ): List<ParsedCertificate> {
        if (chain.isEmpty() || chain.any { it !is X509Certificate }) invalidCertificate()
        return try {
            chain.map { source ->
                val der = source.encoded?.copyOf() ?: invalidCertificate()
                val input = ByteArrayInputStream(der)
                val parsed =
                    CertificateFactory.getInstance("X.509").generateCertificate(input)
                        as? X509Certificate ?: invalidCertificate()
                if (input.available() != 0 || !MessageDigest.isEqual(der, parsed.encoded)) {
                    invalidCertificate()
                }
                ParsedCertificate(parsed, der)
            }
        } catch (failure: TargetTlsClientIdentityException.InvalidCertificate) {
            throw failure
        } catch (failure: Exception) {
            throw TargetTlsClientIdentityException.InvalidCertificate(failure)
        }
    }

    private fun requireP256(certificate: X509Certificate) {
        val key = certificate.publicKey as? ECPublicKey ?: invalidCertificate()
        val actual = key.params ?: invalidCertificate()
        val expected =
            AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec(P256_CURVE))
                getParameterSpec(ECParameterSpec::class.java)
            }
        val actualField = actual.curve.field as? ECFieldFp ?: invalidCertificate()
        val expectedField = expected.curve.field as? ECFieldFp ?: invalidCertificate()
        if (
            actualField.p != expectedField.p ||
                actual.curve.a != expected.curve.a ||
                actual.curve.b != expected.curve.b ||
                actual.generator != expected.generator ||
                actual.order != expected.order ||
                actual.cofactor != expected.cofactor
        ) {
            invalidCertificate()
        }
    }

    private fun runProbe(
        backend: TargetTlsClientIdentityBackend,
        privateKey: PrivateKey,
        leaf: X509Certificate,
    ) {
        try {
            val input = SIGNATURE_PROBE.copyOf()
            val signature = backend.signProbe(privateKey, input.copyOf())
            if (!backend.verifyProbe(leaf.publicKey, input, signature.copyOf())) {
                throw TargetTlsClientIdentityException.ProbeFailure()
            }
        } catch (failure: TargetTlsClientIdentityException.ProbeFailure) {
            throw failure
        } catch (failure: Exception) {
            throw TargetTlsClientIdentityException.ProbeFailure(failure)
        }
    }

    private fun generationSpec(now: Instant, random: SecureRandom) =
        TargetTlsClientGenerationSpec(
            curve = P256_CURVE,
            digest = SHA256,
            userAuthenticationRequired = false,
            strongBoxBacked = false,
            certificateSubject = X500Principal("CN=TEESimulator Target TLS v1"),
            certificateSerialNumber = randomSerial(random),
            notBefore = Date.from(now.minus(1, ChronoUnit.DAYS)),
            notAfter = Date.from(now.atZone(ZoneOffset.UTC).plusYears(20).toInstant()),
        )

    private fun randomSerial(random: SecureRandom): BigInteger {
        val bytes = ByteArray(16)
        do {
            random.nextBytes(bytes)
        } while (bytes.all { it == 0.toByte() })
        return BigInteger(1, bytes)
    }

    private fun invalidKey(): Nothing = throw TargetTlsClientIdentityException.InvalidKey()

    private fun invalidCertificate(): Nothing =
        throw TargetTlsClientIdentityException.InvalidCertificate()

    private inline fun <T> backendCall(block: () -> T): T =
        try {
            block()
        } catch (failure: TargetTlsClientIdentityException) {
            throw failure
        } catch (failure: Exception) {
            throw TargetTlsClientIdentityException.BackendFailure(failure)
        }

    private data class ParsedCertificate(val certificate: X509Certificate, val der: ByteArray)

    private data class ValidatedIdentity(
        val material: TargetTlsClientBackendMaterial,
        val chain: List<ByteArray>,
        val pin: SpkiPin,
    )

    private const val ROOT_UID = 0
    private const val P256_CURVE = "secp256r1"
    private const val SHA256 = "SHA-256"
    private val SIGNATURE_PROBE =
        "TEESimulator\u0000target-tls-client-identity\u0000v1".encodeToByteArray()
    private val identityMutationLock = Any()
}
