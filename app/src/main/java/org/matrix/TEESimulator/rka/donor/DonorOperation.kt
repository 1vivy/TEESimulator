package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

enum class DonorAlgorithm {
    EC
}

enum class DonorCurve {
    P256,
    P384,
}

enum class DonorPurpose {
    SIGN
}

enum class DonorDigest {
    SHA256
}

enum class DonorSecurityLevel {
    TEE
}

enum class DonorOrigin {
    GENERATED
}

data class DonorKeyCharacteristics(
    val securityLevel: DonorSecurityLevel,
    val algorithm: DonorAlgorithm,
    val curve: DonorCurve,
    val purpose: DonorPurpose,
    val digest: DonorDigest,
    val origin: DonorOrigin,
    val noAuthRequired: Boolean,
) {
    companion object {
        fun exact(): DonorKeyCharacteristics =
            DonorKeyCharacteristics(
                DonorSecurityLevel.TEE,
                DonorAlgorithm.EC,
                DonorCurve.P256,
                DonorPurpose.SIGN,
                DonorDigest.SHA256,
                DonorOrigin.GENERATED,
                true,
            )
    }
}

data class DonorKeyParameters(
    val securityLevel: DonorSecurityLevel,
    val algorithm: DonorAlgorithm,
    val curve: DonorCurve,
    val purpose: DonorPurpose,
    val digest: DonorDigest,
    val noAuthRequired: Boolean,
    val challenge: ByteArray,
    val aaid: ByteArray,
) {
    init {
        require(challenge.size in 16..64)
        require(aaid.isNotEmpty() && aaid.size <= 131_072)
    }

    companion object {
        fun exact(challenge: ByteArray, aaid: ByteArray): DonorKeyParameters =
            DonorKeyParameters(
                DonorSecurityLevel.TEE,
                DonorAlgorithm.EC,
                DonorCurve.P256,
                DonorPurpose.SIGN,
                DonorDigest.SHA256,
                true,
                challenge.copyOf(),
                aaid.copyOf(),
            )
    }
}

internal class DonorAttestationKey(
    keyBlob: ByteArray,
    val issuerSubjectName: ByteArray,
    val attestKeyParams: List<Nothing> = emptyList(),
) {
    private val keyBlob = keyBlob.copyOf()

    internal fun withBlob(action: (ByteArray) -> Unit) = action(keyBlob)

    override fun toString(): String = "DonorAttestationKey(redacted)"
}

internal data class DonorKeyCreation(
    val keyBlob: ByteArray,
    val characteristics: DonorKeyCharacteristics,
    val certificateChain: List<ByteArray>,
)

internal interface DonorOperationEndpoint {
    fun updateAad(input: ByteArray)

    fun update(input: ByteArray): ByteArray

    fun finish(input: ByteArray): ByteArray

    fun abort()
}

internal interface DonorKeyMintDevice {
    fun generate(
        parameters: DonorKeyParameters,
        attestationKey: DonorAttestationKey,
    ): DonorKeyCreation

    fun begin(keyBlob: ByteArray): DonorOperationEndpoint

    fun delete(keyBlob: ByteArray)
}

class DonorKeyHandle private constructor(private val value: ByteArray) {
    fun copyBytes(): ByteArray = value.copyOf()

    internal fun key(): String = value.hex()

    override fun equals(other: Any?): Boolean =
        other is DonorKeyHandle && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "DonorKeyHandle(redacted)"

    companion object {
        fun of(bytes: ByteArray): DonorKeyHandle {
            require(bytes.size == 16)
            return DonorKeyHandle(bytes.copyOf())
        }
    }
}

class DonorOperationHandle private constructor(private val value: ByteArray) {
    fun copyBytes(): ByteArray = value.copyOf()

    internal fun matches(other: DonorOperationHandle): Boolean = value.contentEquals(other.value)

    override fun toString(): String = "DonorOperationHandle(redacted)"

    companion object {
        internal fun fresh(random: SecureRandom): DonorOperationHandle =
            DonorOperationHandle(ByteArray(16).also(random::nextBytes))

        fun of(bytes: ByteArray): DonorOperationHandle {
            require(bytes.size == 16)
            return DonorOperationHandle(bytes.copyOf())
        }
    }
}

class DonorPublicBytes private constructor(private val value: ByteArray) : AutoCloseable {
    private val closed = AtomicBoolean()

    fun copyBytes(): ByteArray {
        check(!closed.get())
        return value.copyOf()
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) value.fill(0)
    }

    override fun toString(): String = "DonorPublicBytes(length=${value.size})"

    companion object {
        fun of(bytes: ByteArray): DonorPublicBytes = DonorPublicBytes(bytes.copyOf())
    }
}

internal class LiveDonorOperation(
    val handle: DonorOperationHandle,
    val key: DonorKeyHandle,
    val endpoint: DonorOperationEndpoint,
) {
    private val signedInput = ByteArrayOutputStream()
    var updated = false
        private set

    fun append(input: ByteArray) {
        signedInput.write(input)
        updated = true
    }

    fun completeInput(finalInput: ByteArray): ByteArray = signedInput.toByteArray() + finalInput
}

internal fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
