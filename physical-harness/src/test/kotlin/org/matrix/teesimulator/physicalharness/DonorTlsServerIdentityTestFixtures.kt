package org.matrix.teesimulator.physicalharness

import java.math.BigInteger
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class DonorTlsServerIdentityTestPki(private val now: Instant) {
    fun selfSigned(
        curve: String = P256,
        notBefore: Instant = now.minus(1, ChronoUnit.DAYS),
        notAfter: Instant = now.plus(1, ChronoUnit.DAYS),
    ): DonorTlsTestIdentity {
        val keys = keyPair(curve)
        val subject = X500Name("CN=donor-tls-test")
        return DonorTlsTestIdentity(
            keys,
            certificate(subject, subject, keys, keys, notBefore, notAfter, curve),
        )
    }

    fun signedByAnotherKey(): DonorTlsTestIdentity {
        val subjectKeys = keyPair(P256)
        val issuerKeys = keyPair(P256)
        return DonorTlsTestIdentity(
            subjectKeys,
            certificate(
                issuer = X500Name("CN=other-issuer"),
                subject = X500Name("CN=donor-tls-test"),
                subjectKeys = subjectKeys,
                issuerKeys = issuerKeys,
                notBefore = now.minus(1, ChronoUnit.DAYS),
                notAfter = now.plus(1, ChronoUnit.DAYS),
                curve = P256,
            ),
        )
    }

    private fun certificate(
        issuer: X500Name,
        subject: X500Name,
        subjectKeys: KeyPair,
        issuerKeys: KeyPair,
        notBefore: Instant,
        notAfter: Instant,
        curve: String,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.ONE,
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                subjectKeys.public,
            )
        val signatureAlgorithm = if (curve == P384) "SHA384withECDSA" else "SHA256withECDSA"
        val signer = JcaContentSignerBuilder(signatureAlgorithm).build(issuerKeys.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun keyPair(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair()

    companion object {
        const val P256 = "secp256r1"
        const val P384 = "secp384r1"
    }
}

internal data class DonorTlsTestIdentity(val keyPair: KeyPair, val certificate: X509Certificate)

internal class FakeDonorTlsServerIdentityBackend(
    @Volatile var aliasPresent: Boolean,
    var key: Key?,
    var securityLevel: BackendSecurityLevel,
    var certificateChain: List<Certificate>,
    val providerKeyStore: KeyStore = emptyKeyStore(),
    keyPassword: CharArray? = null,
) : DonorTlsServerIdentityBackend {
    val calls = CopyOnWriteArrayList<String>()
    val signedInputs = CopyOnWriteArrayList<ByteArray>()
    val verifiedInputs = CopyOnWriteArrayList<ByteArray>()
    val keyPassword = keyPassword?.copyOf()
    @Volatile var generateCount = 0
    @Volatile var deleteCount = 0
    @Volatile var generationSpec: DonorTlsServerGenerationSpec? = null
    var containsFailure: RuntimeException? = null
    var loadFailure: RuntimeException? = null
    var signFailure: RuntimeException? = null
    var verifyFailure: RuntimeException? = null
    var deleteFailure: RuntimeException? = null
    var verifyResult = true

    @Synchronized
    override fun containsAlias(alias: String): Boolean {
        calls += "contains:$alias"
        containsFailure?.let { throw it }
        return aliasPresent
    }

    @Synchronized
    override fun generate(alias: String, spec: DonorTlsServerGenerationSpec) {
        calls += "generate:$alias"
        generateCount += 1
        generationSpec = spec
        aliasPresent = true
    }

    @Synchronized
    override fun load(alias: String): DonorTlsServerBackendMaterial? {
        calls += "load:$alias"
        loadFailure?.let { throw it }
        if (!aliasPresent) return null
        return DonorTlsServerBackendMaterial(
            key = key,
            securityLevel = securityLevel,
            certificateChain = certificateChain,
            keyStore = providerKeyStore,
            keyPassword = keyPassword,
        )
    }

    override fun signProbe(privateKey: PrivateKey, input: ByteArray): ByteArray {
        calls += "sign"
        signedInputs += input.copyOf()
        signFailure?.let { throw it }
        return byteArrayOf(5, 4, 3, 2, 1)
    }

    override fun verifyProbe(
        publicKey: PublicKey,
        input: ByteArray,
        signature: ByteArray,
    ): Boolean {
        calls += "verify"
        verifiedInputs += input.copyOf()
        verifyFailure?.let { throw it }
        return verifyResult
    }

    @Synchronized
    override fun delete(alias: String) {
        calls += "delete:$alias"
        deleteCount += 1
        deleteFailure?.let { throw it }
        aliasPresent = false
    }

    private companion object {
        fun emptyKeyStore(): KeyStore = KeyStore.getInstance("PKCS12").apply { load(null, null) }
    }
}

internal class TestNonExportablePrivateKey(private val keyAlgorithm: String = "EC") : PrivateKey {
    override fun getAlgorithm(): String = keyAlgorithm

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null
}

internal data object TestNonPrivateKey : Key {
    override fun getAlgorithm(): String = "EC"

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null
}

internal class TestNonX509Certificate(private val key: PublicKey) : Certificate("test") {
    override fun getEncoded(): ByteArray = byteArrayOf(1, 2, 3)

    override fun verify(key: PublicKey) = Unit

    override fun verify(key: PublicKey, sigProvider: String) = Unit

    override fun toString(): String = "test certificate"

    override fun getPublicKey(): PublicKey = key
}

internal class TestFixedSecureRandom(private vararg val outputs: ByteArray) : SecureRandom() {
    private var index = 0

    override fun nextBytes(bytes: ByteArray) {
        val output = outputs[index.coerceAtMost(outputs.lastIndex)]
        index += 1
        require(output.size == bytes.size)
        output.copyInto(bytes)
    }
}
