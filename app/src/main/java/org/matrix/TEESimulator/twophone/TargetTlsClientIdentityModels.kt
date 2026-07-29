package org.matrix.TEESimulator.twophone

import java.math.BigInteger
import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.matrix.teesimulator.twophone.SpkiPin

sealed class TargetTlsClientIdentityException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class AliasAlreadyExists :
        TargetTlsClientIdentityException("target TLS client identity already exists")

    class IdentityNotFound :
        TargetTlsClientIdentityException("target TLS client identity not found")

    class InvalidKey(cause: Throwable? = null) :
        TargetTlsClientIdentityException("invalid target TLS client key", cause)

    class InvalidCertificate(cause: Throwable? = null) :
        TargetTlsClientIdentityException("invalid target TLS client certificate", cause)

    class PinMismatch : TargetTlsClientIdentityException("target TLS client pin mismatch")

    class ProbeFailure(cause: Throwable? = null) :
        TargetTlsClientIdentityException("target TLS client signature probe failed", cause)

    class BackendFailure(cause: Throwable) :
        TargetTlsClientIdentityException("AndroidKeyStore target TLS operation failed", cause)
}

class ProvisionedTargetTlsClientPublicMaterial
internal constructor(
    val alias: String,
    leafCertificateDer: ByteArray,
    certificateChainDer: List<ByteArray>,
    val pin: SpkiPin,
) {
    private val stableLeaf = leafCertificateDer.copyOf()
    private val stableChain = certificateChainDer.map(ByteArray::copyOf)

    val leafCertificateDer: ByteArray
        get() = stableLeaf.copyOf()

    val certificateChainDer: List<ByteArray>
        get() = stableChain.map(ByteArray::copyOf)
}

class OpenedTargetTlsClientIdentity
internal constructor(
    val alias: String,
    val keyStore: KeyStore,
    keyPassword: CharArray?,
    certificateChainDer: List<ByteArray>,
    val pin: SpkiPin,
) {
    private val stablePassword = keyPassword?.copyOf()
    private val stableChain = certificateChainDer.map(ByteArray::copyOf)

    val keyPassword: CharArray?
        get() = stablePassword?.copyOf()

    val certificateChainDer: List<ByteArray>
        get() = stableChain.map(ByteArray::copyOf)
}

internal enum class TargetTlsSecurityLevel {
    TRUSTED_ENVIRONMENT,
    SOFTWARE,
    STRONGBOX,
    UNKNOWN,
}

internal data class TargetTlsClientGenerationSpec(
    val curve: String,
    val digest: String,
    val userAuthenticationRequired: Boolean,
    val strongBoxBacked: Boolean,
    val certificateSubject: X500Principal,
    val certificateSerialNumber: BigInteger,
    private val notBefore: Date,
    private val notAfter: Date,
) {
    val certificateNotBefore: Date
        get() = Date(notBefore.time)

    val certificateNotAfter: Date
        get() = Date(notAfter.time)
}

internal class TargetTlsClientBackendMaterial(
    val key: Key?,
    val ownerUid: Int,
    val securityLevel: TargetTlsSecurityLevel,
    certificateChain: List<Certificate>,
    val keyStore: KeyStore,
    keyPassword: CharArray?,
) {
    val certificateChain = certificateChain.toList()
    private val stablePassword = keyPassword?.copyOf()

    val keyPassword: CharArray?
        get() = stablePassword?.copyOf()
}

internal interface TargetTlsClientIdentityBackend {
    fun containsAlias(alias: String): Boolean

    fun generate(alias: String, spec: TargetTlsClientGenerationSpec)

    fun load(alias: String): TargetTlsClientBackendMaterial?

    fun signProbe(privateKey: PrivateKey, input: ByteArray): ByteArray

    fun verifyProbe(publicKey: PublicKey, input: ByteArray, signature: ByteArray): Boolean

    fun delete(alias: String)
}
